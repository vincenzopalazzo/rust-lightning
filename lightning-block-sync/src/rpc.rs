//! Simple RPC client implementation which implements [`BlockSource`] against a Bitcoin Core RPC
//! endpoint.

use crate::gossip::UtxoSource;
use crate::http::{HttpClient, HttpEndpoint, HttpError, JsonResponse};
use crate::{AsyncBlockSourceResult, BlockData, BlockHeaderData, BlockSource};

use bitcoin::hash_types::BlockHash;
use bitcoin::OutPoint;

use std::sync::Mutex;

use serde_json;

use std::convert::TryFrom;
use std::convert::TryInto;
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};

/// An error returned by the RPC server.
#[derive(Debug)]
pub struct RpcError {
	/// The error code.
	pub code: i64,
	/// The error message.
	pub message: String,
}

impl fmt::Display for RpcError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "RPC error {}: {}", self.code, self.message)
	}
}

impl Error for RpcError {}

/// A simple RPC client for calling methods using HTTP `POST`.
///
/// Implements [`BlockSource`] and may return an `Err` containing [`RpcError`]. See
/// [`RpcClient::call_method`] for details.
pub struct RpcClient {
	basic_auth: String,
	endpoint: HttpEndpoint,
	client: Mutex<Option<HttpClient>>,
	id: AtomicUsize,
}

impl RpcClient {
	/// Creates a new RPC client connected to the given endpoint with the provided credentials. The
	/// credentials should be a base64 encoding of a user name and password joined by a colon, as is
	/// required for HTTP basic access authentication.
	pub fn new(credentials: &str, endpoint: HttpEndpoint) -> Self {
		Self {
			basic_auth: "Basic ".to_string() + credentials,
			endpoint,
			client: Mutex::new(None),
			id: AtomicUsize::new(0),
		}
	}

	/// Calls a method with the response encoded in JSON format and interpreted as type `T`.
	///
	/// When an `Err` is returned, [`std::io::Error::into_inner`] may contain an [`RpcError`] if
	/// [`std::io::Error::kind`] is [`std::io::ErrorKind::Other`].
	pub async fn call_method<T>(
		&self, method: &str, params: &[serde_json::Value],
	) -> std::io::Result<T>
	where
		JsonResponse: TryFrom<Vec<u8>, Error = std::io::Error> + TryInto<T, Error = std::io::Error>,
	{
		let host = format!("{}:{}", self.endpoint.host(), self.endpoint.port());
		let uri = self.endpoint.path();
		let content = serde_json::json!({
			"method": method,
			"params": params,
			"id": &self.id.fetch_add(1, Ordering::AcqRel).to_string()
		});

		let reserved_client = self.client.lock().unwrap().take();
		let mut client = if let Some(client) = reserved_client {
			client
		} else {
			HttpClient::connect(&self.endpoint)?
		};
		let http_response =
			client.post::<JsonResponse>(&uri, &host, &self.basic_auth, content).await;
		*self.client.lock().unwrap() = Some(client);

		let mut response = match http_response {
			Ok(JsonResponse(response)) => response,
			Err(e) if e.kind() == std::io::ErrorKind::Other => {
				match e.get_ref().unwrap().downcast_ref::<HttpError>() {
					Some(http_error) => match JsonResponse::try_from(http_error.contents.clone()) {
						Ok(JsonResponse(response)) => response,
						Err(_) => Err(e)?,
					},
					None => Err(e)?,
				}
			},
			Err(e) => Err(e)?,
		};

		if !response.is_object() {
			return Err(std::io::Error::new(
				std::io::ErrorKind::InvalidData,
				"expected JSON object",
			));
		}

		let error = &response["error"];
		if !error.is_null() {
			// TODO: Examine error code for a more precise std::io::ErrorKind.
			let rpc_error = RpcError {
				code: error["code"].as_i64().unwrap_or(-1),
				message: error["message"].as_str().unwrap_or("unknown error").to_string(),
			};
			return Err(std::io::Error::new(std::io::ErrorKind::Other, rpc_error));
		}

		let result = match response.get_mut("result") {
			Some(result) => result.take(),
			None => {
				return Err(std::io::Error::new(
					std::io::ErrorKind::InvalidData,
					"expected JSON result",
				))
			},
		};

		JsonResponse(result).try_into()
	}
}

impl BlockSource for RpcClient {
	fn get_header<'a>(
		&'a self, header_hash: &'a BlockHash, _height: Option<u32>,
	) -> AsyncBlockSourceResult<'a, BlockHeaderData> {
		Box::pin(async move {
			let header_hash = serde_json::json!(header_hash.to_string());
			Ok(self.call_method("getblockheader", &[header_hash]).await?)
		})
	}

	fn get_block<'a>(
		&'a self, header_hash: &'a BlockHash,
	) -> AsyncBlockSourceResult<'a, BlockData> {
		Box::pin(async move {
			let header_hash = serde_json::json!(header_hash.to_string());
			let verbosity = serde_json::json!(0);
			Ok(BlockData::FullBlock(self.call_method("getblock", &[header_hash, verbosity]).await?))
		})
	}

	fn get_best_block<'a>(&'a self) -> AsyncBlockSourceResult<'a, (BlockHash, Option<u32>)> {
		Box::pin(async move { Ok(self.call_method("getblockchaininfo", &[]).await?) })
	}
}

impl UtxoSource for RpcClient {
	fn get_block_hash_by_height<'a>(
		&'a self, block_height: u32,
	) -> AsyncBlockSourceResult<'a, BlockHash> {
		Box::pin(async move {
			let height_param = serde_json::json!(block_height);
			Ok(self.call_method("getblockhash", &[height_param]).await?)
		})
	}

	fn is_output_unspent<'a>(&'a self, outpoint: OutPoint) -> AsyncBlockSourceResult<'a, bool> {
		Box::pin(async move {
			let txid_param = serde_json::json!(outpoint.txid.to_string());
			let vout_param = serde_json::json!(outpoint.vout);
			let include_mempool = serde_json::json!(false);
			let utxo_opt: serde_json::Value =
				self.call_method("gettxout", &[txid_param, vout_param, include_mempool]).await?;
			Ok(!utxo_opt.is_null())
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::http::client_tests::{HttpServer, MessageBody};

	use bitcoin::hashes::Hash;

	/// Credentials encoded in base64.
	const CREDENTIALS: &'static str = "dXNlcjpwYXNzd29yZA==";

	/// Converts a JSON value into `u64`.
	impl TryInto<u64> for JsonResponse {
		type Error = std::io::Error;

		fn try_into(self) -> std::io::Result<u64> {
			match self.0.as_u64() {
				None => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "not a number")),
				Some(n) => Ok(n),
			}
		}
	}

	#[tokio::test]
	async fn call_method_returning_unknown_response() {
		let server = HttpServer::responding_with_not_found();
		let client = RpcClient::new(CREDENTIALS, server.endpoint());

		match client.call_method::<u64>("getblockcount", &[]).await {
			Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::Other),
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn call_method_returning_malfomred_response() {
		let response = serde_json::json!("foo");
		let server = HttpServer::responding_with_ok(MessageBody::Content(response));
		let client = RpcClient::new(CREDENTIALS, server.endpoint());

		match client.call_method::<u64>("getblockcount", &[]).await {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(e.get_ref().unwrap().to_string(), "expected JSON object");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn call_method_returning_error() {
		let response = serde_json::json!({
			"error": { "code": -8, "message": "invalid parameter" },
		});
		let server = HttpServer::responding_with_server_error(response);
		let client = RpcClient::new(CREDENTIALS, server.endpoint());

		let invalid_block_hash = serde_json::json!("foo");
		match client.call_method::<u64>("getblock", &[invalid_block_hash]).await {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::Other);
				let rpc_error: Box<RpcError> = e.into_inner().unwrap().downcast().unwrap();
				assert_eq!(rpc_error.code, -8);
				assert_eq!(rpc_error.message, "invalid parameter");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn call_method_returning_missing_result() {
		let response = serde_json::json!({});
		let server = HttpServer::responding_with_ok(MessageBody::Content(response));
		let client = RpcClient::new(CREDENTIALS, server.endpoint());

		match client.call_method::<u64>("getblockcount", &[]).await {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(e.get_ref().unwrap().to_string(), "expected JSON result");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn call_method_returning_malformed_result() {
		let response = serde_json::json!({ "result": "foo" });
		let server = HttpServer::responding_with_ok(MessageBody::Content(response));
		let client = RpcClient::new(CREDENTIALS, server.endpoint());

		match client.call_method::<u64>("getblockcount", &[]).await {
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
				assert_eq!(e.get_ref().unwrap().to_string(), "not a number");
			},
			Ok(_) => panic!("Expected error"),
		}
	}

	#[tokio::test]
	async fn call_method_returning_valid_result() {
		let response = serde_json::json!({ "result": 654470 });
		let server = HttpServer::responding_with_ok(MessageBody::Content(response));
		let client = RpcClient::new(CREDENTIALS, server.endpoint());

		match client.call_method::<u64>("getblockcount", &[]).await {
			Err(e) => panic!("Unexpected error: {:?}", e),
			Ok(count) => assert_eq!(count, 654470),
		}
	}

	#[tokio::test]
	async fn fails_to_fetch_spent_utxo() {
		let response = serde_json::json!({ "result": null });
		let server = HttpServer::responding_with_ok(MessageBody::Content(response));
		let client = RpcClient::new(CREDENTIALS, server.endpoint());
		let outpoint = OutPoint::new(bitcoin::Txid::from_byte_array([0; 32]), 0);
		let unspent_output = client.is_output_unspent(outpoint).await.unwrap();
		assert_eq!(unspent_output, false);
	}

	#[tokio::test]
	async fn fetches_utxo() {
		let response = serde_json::json!({ "result": {"bestblock": 1, "confirmations": 42}});
		let server = HttpServer::responding_with_ok(MessageBody::Content(response));
		let client = RpcClient::new(CREDENTIALS, server.endpoint());
		let outpoint = OutPoint::new(bitcoin::Txid::from_byte_array([0; 32]), 0);
		let unspent_output = client.is_output_unspent(outpoint).await.unwrap();
		assert_eq!(unspent_output, true);
	}
}

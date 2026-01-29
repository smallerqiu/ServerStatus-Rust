// #![allow(unused)]
use std::str::FromStr;
use std::thread;
use std::time::Duration;
use tonic::transport::Channel;
use tonic::{metadata::MetadataValue, Request};
use tower::timeout::Timeout;
use url::Url;

use stat_common::server_status::server_status_client::ServerStatusClient;
use stat_common::server_status::StatRequest;

use crate::sample_all;
use crate::Args;

// ===== 新增导入 =====
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer}
};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::sync::Arc;
use std::io::BufReader;

pub async fn report(args: &Args, stat_base: &mut StatRequest) -> anyhow::Result<()> {
    let auth_user: String;
    let ssr_auth: &[u8];
    if args.gid.is_empty() {
        auth_user = args.user.to_string();
        ssr_auth = b"single";
    } else {
        auth_user = args.gid.to_string();
        ssr_auth = b"group";
    }
    let token = MetadataValue::try_from(format!("{}@_@{}", auth_user, args.pass))?;

    let addr = args.addr.replace("grpcs://", "https://");
    let u = Url::parse(&addr)?;

    let client_config = if args.mtls {
        // ===== mTLS 模式 =====
        let tls_dir = std::path::PathBuf::from_str(&args.tls_dir)?;
        
        // 加载 CA 证书
        let ca_pem = std::fs::read_to_string(tls_dir.join("ca.pem"))?;
        let mut root_store = RootCertStore::empty();
        for cert_result in certs(&mut BufReader::new(ca_pem.as_bytes())) {
            let cert = cert_result?;
            root_store.add(CertificateDer::from(cert))?;
        }

        // 加载客户端证书
        let client_cert_pem = std::fs::read_to_string(tls_dir.join("client.pem"))?;
        let client_certs: Vec<CertificateDer> = certs(&mut BufReader::new(client_cert_pem.as_bytes()))?
            .into_iter()
            .map(CertificateDer::from)
            .collect();

        // 加载客户端私钥 (PKCS#8)
        let client_key_pem = std::fs::read_to_string(tls_dir.join("client.key"))?;
        let keys: Vec<Vec<u8>> = pkcs8_private_keys(&mut BufReader::new(client_key_pem.as_bytes()))?;
        if keys.is_empty() {
            anyhow::bail!("No PKCS#8 private key found in client.key");
        }
        let client_key = PrivateKeyDer::Pkcs8(keys[0].clone().into());

        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(client_certs, client_key)?
    } else if addr.starts_with("https://") {
        // ===== 普通 TLS 模式 =====
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    } else {
        // 明文 gRPC（不推荐，但保留兼容性）
        anyhow::bail!("Plaintext gRPC is not supported. Use grpcs:// or enable mTLS.");
    };

    // ✅ 关键：使用 https:// + .tls_config(Arc::new(...))
    let channel = Channel::from_shared(addr)?
        .tls_config(Arc::new(client_config))?  // ← 这个方法仍然存在！
        .connect()
        .await?;

    let timeout_channel = Timeout::new(channel, Duration::from_millis(3000));
    let grpc_client = ServerStatusClient::with_interceptor(timeout_channel, move |mut req: Request<()>| {
        req.metadata_mut().insert("authorization", token.clone());
        req.metadata_mut()
            .insert("ssr-auth", MetadataValue::try_from(ssr_auth).unwrap());
        Ok(req)
    });

    loop {
        let stat_rt = sample_all(args, stat_base);
        let mut client = grpc_client.clone();

        tokio::spawn(async move {
            let request = tonic::Request::new(stat_rt);
            match client.report(request).await {
                Ok(resp) => {
                    info!("grpc report resp => {:?}", resp);
                }
                Err(status) => {
                    error!("grpc report status => {:?}", status);
                }
            }
        });

        thread::sleep(Duration::from_secs(args.report_interval));
    }
}
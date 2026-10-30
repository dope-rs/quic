use crate::common::runtime;
use dope_quic::conn::id;
use dope_quic::conn::life::accept;
use dope_quic::conn::life::options::Options;
use dope_quic::proto::epoch;
use dope_quic::runtime::mux::builder::Builder;
use dope_quic::runtime::mux::handler;
use dope_quic::runtime::mux::handler::hook::life::{create::Unit, ready};
use dope_quic::runtime::mux::handler::hook::set::{On, Set};
use dope_quic::runtime::mux::handler::hook::wire::cert;
use dope_quic::runtime::mux::router::Router;
use dope_tls::config::Ext as _;
use o3::buffer::storage;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::{
    fs, io, net,
    path::{Path, PathBuf},
    pin, process, time,
};

#[derive(Default)]
pub struct Events {
    pub established: Vec<id::Handle>,
    pub certificates: usize,
}

impl handler::Handler<0, Vec<u8>, storage::Shared> for Events {
    type Connection = ();
    type Create = Unit;
    type Events = Set<On>;
}

impl ready::Sink<0, Vec<u8>, storage::Shared, id::Static> for Events {
    fn established(event: ready::Event<'_, Self, 0, Vec<u8>, storage::Shared, id::Static>) {
        let (mut events, _, handle, _) = event.into();
        events.established.push(handle);
    }
}

impl cert::Sink<0, id::Static> for Events {
    fn certificate(event: cert::Event<'_, '_, Self, 0, id::Static>) {
        let (mut events, _, _, _) = event.into_parts();
        events.certificates += 1;
    }
}

pub struct Identity {
    pub key: Vec<u8>,
    pub chain: [Vec<u8>; 1],
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Runtime(runtime::Error),
    Sent { expected: usize, actual: usize },
}

#[derive(Debug)]
pub enum Init {
    Io(io::Error),
    Command {
        args: &'static [&'static str],
        directory: PathBuf,
        output: process::Output,
    },
}

#[derive(Debug)]
pub enum Setup {
    Tls(dope_tls::Error),
    Runtime(runtime::Error),
    Io(io::Error),
}

impl Identity {
    pub fn new(root: &Path) -> Result<Self, Init> {
        let commands: [&'static [&'static str]; 4] = [
            &[
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-out",
                "key.pem",
            ],
            &[
                "pkcs8", "-topk8", "-nocrypt", "-in", "key.pem", "-outform", "DER", "-out",
                "key.der",
            ],
            &[
                "req",
                "-new",
                "-x509",
                "-key",
                "key.pem",
                "-sha256",
                "-days",
                "1",
                "-subj",
                "/CN=127.0.0.1",
                "-addext",
                "subjectAltName=IP:127.0.0.1",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-addext",
                "keyUsage=critical,digitalSignature",
                "-addext",
                "extendedKeyUsage=serverAuth,clientAuth",
                "-out",
                "cert.pem",
            ],
            &[
                "x509", "-in", "cert.pem", "-outform", "DER", "-out", "cert.der",
            ],
        ];
        for args in commands {
            let mut command = process::Command::new("openssl");
            command.args(args).current_dir(root);
            let output = command.output().map_err(Init::Io)?;
            if !output.status.success() {
                return Err(Init::Command {
                    args,
                    directory: root.to_path_buf(),
                    output,
                });
            }
        }
        Ok(Self {
            key: fs::read(root.join("key.der")).map_err(Init::Io)?,
            chain: [fs::read(root.join("cert.der")).map_err(Init::Io)?],
        })
    }
}

pub struct Peer<'a, F: FnMut(io::Result<process::ExitStatus>)> {
    child: process::Child,
    root: &'a Path,
    report: F,
}

impl<'a, F: FnMut(io::Result<process::ExitStatus>)> Peer<'a, F> {
    pub fn new(root: &'a Path, address: net::SocketAddr, report: F) -> io::Result<Self> {
        let child = process::Command::new("openssl")
            .args([
                "s_client",
                "-quic",
                "-connect",
                &address.to_string(),
                "-alpn",
                "h3",
                "-CAfile",
                "cert.pem",
                "-verify_ip",
                "127.0.0.1",
                "-verify_return_error",
                "-brief",
                "-ign_eof",
            ])
            .current_dir(root)
            .stdin(process::Stdio::null())
            .stdout(fs::File::create(root.join("stdout"))?)
            .stderr(fs::File::create(root.join("stderr"))?)
            .spawn()?;
        Ok(Self {
            child,
            root,
            report,
        })
    }

    pub fn diagnostic(&self) -> io::Result<String> {
        fs::read_to_string(self.root.join("stderr"))
    }

    pub fn verified(&self) -> io::Result<bool> {
        Ok(self.diagnostic()?.contains("Verification: OK"))
    }

    pub fn status(&mut self) -> io::Result<Option<process::ExitStatus>> {
        self.child.try_wait()
    }
}

impl<F: FnMut(io::Result<process::ExitStatus>)> Drop for Peer<'_, F> {
    fn drop(&mut self) {
        let result = self.child.try_wait().and_then(|status| {
            if status.is_none() {
                self.child.kill()?;
            }
            self.child.wait()
        });
        (self.report)(result);
    }
}

pub struct Server {
    pub router: Router<Events>,
    socket: net::UdpSocket,
    packet: Vec<u8>,
    pub received: usize,
    pub sent: usize,
}

impl Server {
    pub fn new(input: &Identity) -> Result<Self, Setup> {
        let mut tls = ServerConfig::try_tls13()
            .map_err(Setup::Tls)?
            .with_no_client_auth()
            .with_single_cert(
                input
                    .chain
                    .iter()
                    .cloned()
                    .map(CertificateDer::from)
                    .collect(),
                PrivatePkcs8KeyDer::from(input.key.clone()).into(),
            )
            .map_err(dope_tls::Error::Tls)
            .map_err(Setup::Tls)?;
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let options = Options::builder()
            .try_build()
            .map_err(runtime::Error::Options)
            .map_err(Setup::Runtime)?;
        let auth = accept::Authority::new(tls, options)
            .map_err(runtime::Error::Connect)
            .map_err(Setup::Runtime)?;
        let router = Builder::server(Events::default(), auth)
            .build()
            .map_err(runtime::Error::Storage)
            .map_err(Setup::Runtime)?;
        let socket = net::UdpSocket::bind((net::Ipv4Addr::LOCALHOST, 0)).map_err(Setup::Io)?;
        socket
            .set_read_timeout(Some(time::Duration::from_millis(2)))
            .map_err(Setup::Io)?;
        Ok(Self {
            router,
            socket,
            packet: vec![0; u16::MAX as usize],
            received: 0,
            sent: 0,
        })
    }

    pub fn addr(&self) -> io::Result<net::SocketAddr> {
        self.socket.local_addr()
    }

    pub fn poll(&mut self) -> Result<(), Error> {
        let now = time::Instant::now();
        match self.socket.recv_from(&mut self.packet) {
            Ok((length, from)) => {
                self.received += 1;
                pin::Pin::new(&mut self.router)
                    .observe(now, |mut turn| {
                        turn.protocol()
                            .recv(from, &mut self.packet[..length], epoch::WALL_CLOCK)
                    })
                    .map_err(runtime::Error::Receive)
                    .map_err(Error::Runtime)?;
            }
            Err(cause)
                if matches!(
                    cause.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(cause) => return Err(Error::Io(cause)),
        }
        pin::Pin::new(&mut self.router)
            .observe(now, |mut turn| turn.output().drive())
            .map_err(runtime::Error::Output)
            .map_err(Error::Runtime)?;
        let outgoing: Vec<_> = pin::Pin::new(&mut self.router)
            .observe(now, |mut turn| turn.output().drain().collect());
        for mut outgoing in outgoing {
            let address = outgoing.addr();
            for segment in outgoing.segments_mut() {
                self.sent += 1;
                let actual = self.socket.send_to(segment, address).map_err(Error::Io)?;
                if actual != segment.len() {
                    return Err(Error::Sent {
                        expected: segment.len(),
                        actual,
                    });
                }
            }
            pin::Pin::new(&mut self.router).output().recycle(outgoing);
        }
        Ok(())
    }
}

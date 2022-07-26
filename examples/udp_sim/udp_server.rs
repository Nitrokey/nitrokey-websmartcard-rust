use std::error::Error;
use std::net::UdpSocket;

pub struct UDPServer {
    buf: [u8; 8192],
    socket: UdpSocket,
    addr_target: String,
    data_len: usize,
}

impl UDPServer {
    pub fn new() -> Self {
        let addr = "127.0.0.1:8111";
        let addr_target = "127.0.0.1:7112";
        let socket = UdpSocket::bind(addr).unwrap();
        UDPServer {
            addr_target: addr_target.into(),
            socket,
            buf: [0; 1024 * 8],
            data_len: 0,
        }
    }

    pub fn receive(&mut self) -> Result<&[u8], Box<dyn Error>> {
        println!("\n<?");
        let (amt, _src) = self.socket.recv_from(&mut self.buf)?;
        self.data_len = amt;
        let buf = &mut self.buf[..amt];
        println!("< [{}]{:x?}", buf.len(), buf);
        Ok(buf)
    }

    pub fn send(&self, buf: &[u8]) -> Result<(), Box<dyn Error>> {
        println!("> [{}]{:?}", buf.len(), buf);
        println!("> [{}]{:x?}", buf.len(), buf);
        let sent = self.socket.send_to(buf, self.addr_target.clone())?;
        assert_eq!(sent, buf.len());
        Ok(())
    }
}

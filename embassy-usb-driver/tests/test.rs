use embassy_usb_driver::*;
use std::collections::VecDeque;

struct TestEndpoint {
    info: EndpointInfo,
    packets: VecDeque<Vec<u8>>,
}

impl Endpoint for TestEndpoint {
    fn info(&self) -> &EndpointInfo {
        &self.info
    }

    async fn wait_enabled(&mut self) {}
}

impl EndpointInSinglePacket for TestEndpoint {
    async fn write_one_packet(&mut self, buf: &[u8]) -> Result<(), EndpointError> {
        self.packets.push_back(buf.to_vec());
        Ok(())
    }
}

impl EndpointOutSinglePacket for TestEndpoint {
    async fn read_one_packet(&mut self, buf: &mut [u8]) -> Result<usize, EndpointError> {
        let pkt = self
            .packets
            .pop_front()
            .expect("read more data than provided by the test");
        if pkt.len() > buf.len() {
            Err(EndpointError::BufferOverflow)
        } else {
            buf[..pkt.len()].copy_from_slice(&pkt);
            Ok(pkt.len())
        }
    }
}

#[test]
fn endpoint_in_single_packet() -> Result<(), EndpointError> {
    let mut endpoint = TestEndpoint {
        info: EndpointInfo {
            addr: EndpointAddress::from(0x81),
            ep_type: EndpointType::Interrupt,
            max_packet_size: 64,
            interval_ms: 40,
        },
        packets: VecDeque::new(),
    };

    // Write 250 bytes.
    let buf: [u8; 250] = std::array::from_fn(|n| n as u8);
    embassy_futures::block_on(endpoint.write(&buf))?;

    // The data should have been written as 3 64-byte packets, followed by a 58-byte packet.
    let expected: [Vec<u8>; 4] = [
        (0..64).collect(),
        (64..128).collect(),
        (128..192).collect(),
        (192..250).collect(),
    ];
    assert_eq!(endpoint.packets, expected);

    // A 0-length write should result in a 0-length call to write_one_packet()
    endpoint.packets = VecDeque::new();
    let buf: [u8; 0] = [];
    embassy_futures::block_on(endpoint.write(&buf))?;
    let expected: [Vec<u8>; 1] = [Vec::new()];
    assert_eq!(endpoint.packets, expected);

    Ok(())
}

fn create_test_out_endpoint() -> TestEndpoint {
    // Prepare packets for the test to read
    // - one transfer of 135 bytes of data, in 2 full packets followed by 1 short packet.
    // - one transfer of 128 bytes, in 2 full packets followed by a 0-size packet.
    //   (transfers don't always have to end in a 0-size packet if the caller otherwise
    //   knows the expected transfer length, but we explicitly want to test 0-size packet
    //   handling.)
    let packets = [
        (0..64).collect(),
        (64..128).collect(),
        (128..135).collect(),
        (128..192).collect(),
        (6..70).collect(),
        Vec::<u8>::new(),
    ];

    TestEndpoint {
        info: EndpointInfo {
            addr: EndpointAddress::from(0x01),
            ep_type: EndpointType::Interrupt,
            max_packet_size: 64,
            interval_ms: 40,
        },
        packets: packets.into(),
    }
}

#[test]
fn endpoint_out_single_packet_larger_read_buf() -> Result<(), EndpointError> {
    let mut endpoint = create_test_out_endpoint();

    // The first transfer is 135 bytes.
    let mut buf: [u8; 250] = [0xff; 250];
    let bytes_read = embassy_futures::block_on(endpoint.read(&mut buf))?;
    assert_eq!(bytes_read, 135);
    let expected: [u8; 250] = std::array::from_fn(|n| if n < 135 { n as u8 } else { 0xff });
    assert_eq!(buf, expected);

    // The second transfer is 128 bytes.
    let mut buf: [u8; 250] = [0xff; 250];
    let bytes_read = embassy_futures::block_on(endpoint.read(&mut buf))?;
    assert_eq!(bytes_read, 128);
    let expected: [u8; 250] = std::array::from_fn(|n| {
        if n < 64 {
            n as u8 + 128
        } else if n < 128 {
            n as u8 - 64 + 6
        } else {
            0xff
        }
    });
    assert_eq!(buf, expected);
    Ok(())
}

#[test]
fn endpoint_out_single_packet_exact_read_buf() -> Result<(), EndpointError> {
    let mut endpoint = create_test_out_endpoint();

    // The first transfer is 135 bytes.
    let mut buf: [u8; 135] = [0xff; 135];
    let bytes_read = embassy_futures::block_on(endpoint.read(&mut buf))?;
    assert_eq!(bytes_read, 135);
    let expected: [u8; 135] = std::array::from_fn(|n| n as u8);
    assert_eq!(buf, expected);

    // The second transfer is 128 bytes.
    let mut buf: [u8; 128] = [0xff; 128];
    let bytes_read = embassy_futures::block_on(endpoint.read(&mut buf))?;
    assert_eq!(bytes_read, 128);
    let expected: [u8; 128] = std::array::from_fn(|n| if n < 64 { n as u8 + 128 } else { n as u8 - 64 + 6 });
    assert_eq!(buf, expected);

    // Our second read should not have consumed the final 0-byte packet
    let mut buf: [u8; 0] = [0xff; 0];
    let bytes_read = embassy_futures::block_on(endpoint.read(&mut buf))?;
    assert_eq!(bytes_read, 0);

    Ok(())
}

#[test]
fn endpoint_out_single_packet_buf_overflow() -> Result<(), EndpointError> {
    let mut endpoint = create_test_out_endpoint();

    // Reading with a buffer that is too small, and is not a multiple of the max packet size,
    // should result in a BufferOverflow error.
    let mut buf: [u8; 134] = [0xff; 134];
    let result = embassy_futures::block_on(endpoint.read(&mut buf));
    assert_eq!(Err(EndpointError::BufferOverflow), result);

    Ok(())
}

#[test]
fn endpoint_out_single_packet_partial_transfer() -> Result<(), EndpointError> {
    let mut endpoint = create_test_out_endpoint();

    // We should be able to read a partial transfer if our buffer is a multiple
    // of the max packet size
    let mut buf: [u8; 128] = [0xff; 128];
    let bytes_read = embassy_futures::block_on(endpoint.read(&mut buf))?;
    assert_eq!(bytes_read, 128);
    let expected: [u8; 128] = std::array::from_fn(|n| n as u8);
    assert_eq!(buf, expected);

    // We can now read the remainder in a subsequent read() call
    let mut buf: [u8; 7] = [0xff; 7];
    let bytes_read = embassy_futures::block_on(endpoint.read(&mut buf))?;
    assert_eq!(bytes_read, 7);
    let expected: [u8; 7] = std::array::from_fn(|n| n as u8 + 128);
    assert_eq!(buf, expected);

    Ok(())
}

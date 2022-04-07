use bbqueue::framed::FrameProducer;
use heapless::Vec;

use crate::error::InternalError;
use crate::helpers::LossyStr;
use crate::nom_digest::{DigestResult, Digester};
use crate::queues::ComConsumer;
use crate::ResponseHeader;
use crate::Command;

pub struct IngressManager<
    D,
    const BUF_LEN: usize,
    const RES_CAPACITY: usize,
    const URC_CAPACITY: usize,
> where
    D: Digester,
{
    /// Buffer holding incoming bytes.
    buf: Vec<u8, BUF_LEN>,

    /// The response producer sends responses to the client
    res_p: FrameProducer<'static, RES_CAPACITY>,
    /// The URC producer sends URCs to the client
    urc_p: FrameProducer<'static, URC_CAPACITY>,
    /// The command consumer receives commands from the client
    com_c: ComConsumer,

    /// Digester.
    digester: D,
}

impl<D, const BUF_LEN: usize, const RES_CAPACITY: usize, const URC_CAPACITY: usize>
    IngressManager<D, BUF_LEN, RES_CAPACITY, URC_CAPACITY>
where
    D: Digester,
{
    pub fn new(
        res_p: FrameProducer<'static, RES_CAPACITY>,
        urc_p: FrameProducer<'static, URC_CAPACITY>,
        com_c: ComConsumer,
        digester: D,
    ) -> Self {
        Self {
            buf: Vec::new(),
            res_p,
            urc_p,
            com_c,
            digester,
        }
    }

    /// Write data into the internal buffer raw bytes being the core type allows
    /// the ingress manager to be abstracted over the communication medium.
    ///
    /// This function should be called by the UART Rx, either in a receive
    /// interrupt, or a DMA interrupt, to move data from the peripheral into the
    /// ingress manager receive buffer.
    pub fn write(&mut self, data: &[u8]) {
        // trace!("Write: \"{:?}\"", LossyStr(data));

        if self.buf.extend_from_slice(data).is_err() {
            error!("OVERFLOW DATA! Buffer: {:?}", LossyStr(&self.buf));
            let (header, bytes) = ResponseHeader::as_bytes(&Err(InternalError::Overflow));
            if let Ok(mut grant) = self.res_p.grant(bytes.len() + header.len()) {
                grant[0..header.len()].copy_from_slice(&header);
                grant[header.len()..header.len() + bytes.len()].copy_from_slice(bytes);
                grant.commit(bytes.len() + header.len());
            } else {
                error!("Response queue full!");
            }
        }
    }

    /// Return the current length of the internal buffer
    ///
    /// This can be useful for custom flowcontrol implementations
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns whether the internal buffer is empty
    ///
    /// This can be useful for custom flowcontrol implementations
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return the capacity of the internal buffer
    ///
    /// This can be useful for custom flowcontrol implementations
    pub fn capacity(&self) -> usize {
        self.buf.capacity()
    }

    /// Handle receiving internal config commands from the client.
    fn handle_com(&mut self) {
        if let Some(com) = self.com_c.dequeue() {
            match com {
                Command::Reset => {
                    debug!(
                        "Cleared complete buffer as requested by client [{:?}]",
                        LossyStr(&self.buf),
                    );
                    self.buf.clear();
                }
            }
        }
    }

    pub fn digest(&mut self) {
        // Handle commands every loop to catch timeouts asap
        self.handle_com();

        if let Ok(swallowed) = match self.digester.digest(&self.buf) {
            (DigestResult::None, swallowed) => Ok(swallowed),
            (DigestResult::Prompt(prompt), swallowed) => {
                info!("GOT PROMPT {}", prompt);
                let (header, bytes) = ResponseHeader::as_bytes(&Ok(&[]));
                let grant_len = bytes.len() + header.len();
                if let Ok(mut grant) = self.res_p.grant(grant_len) {
                    grant[..header.len()].copy_from_slice(&header);
                    grant[header.len()..grant_len].copy_from_slice(bytes);
                    grant.commit(grant_len);
                    Ok(swallowed)
                } else {
                    error!("Response queue full!");
                    Err(())
                }
            }
            (DigestResult::Urc(urc_line), swallowed) => {
                if let Ok(mut grant) = self.urc_p.grant(urc_line.len()) {
                    grant.copy_from_slice(urc_line);
                    grant.commit(urc_line.len());
                    Ok(swallowed)
                } else {
                    error!("URC queue full!");
                    Err(())
                }
            }
            (DigestResult::Response(resp), swallowed) => {
                #[cfg(any(feature = "defmt", feature = "log"))]
                match &resp {
                    Ok(r) => {
                        if r.is_empty() {
                            debug!("Received OK")
                        } else {
                            debug!("Received response: \"{:?}\"", LossyStr(r.as_ref()));
                        }
                    }
                    Err(e) => {
                        error!("Received error response {:?}", e);
                    }
                };

                let (header, bytes) = ResponseHeader::as_bytes(&resp);
                let grant_len = bytes.len() + header.len();
                if let Ok(mut grant) = self.res_p.grant(grant_len) {
                    grant[..header.len()].copy_from_slice(&header);
                    grant[header.len()..grant_len].copy_from_slice(bytes);
                    grant.commit(grant_len);
                    Ok(swallowed)
                } else {
                    error!("Response queue full!");
                    Err(())
                }
            }
        } {
            self.buf.rotate_left(swallowed);
            self.buf.truncate(self.buf.len() - swallowed);
            // if !self.buf.is_empty() {
            //     trace!("Buffer remainder: \"{:?}\"", LossyStr(&self.buf));
            // }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{queues, Parser, AtDigester};
    use bbqueue::BBBuffer;
    use heapless::spsc::Queue;

    const TEST_RX_BUF_LEN: usize = 256;
    const TEST_URC_CAPACITY: usize = 10;
    const TEST_RES_CAPACITY: usize = 10;

    enum UrcTestParser {}

    impl Parser for UrcTestParser {
        fn parse<'a>(
            _buf: &'a [u8],
        ) -> Result<(&'a [u8], usize), nom::Err<nom::error::Error<&'a [u8]>>> {
            Err(nom::Err::Incomplete(nom::Needed::Unknown))
        }
    }

    #[test]
    fn overflow() {
        static mut RES_Q: BBBuffer<TEST_RES_CAPACITY> = BBBuffer::new();
        let (res_p, mut res_c) = unsafe { RES_Q.try_split_framed().unwrap() };

        static mut URC_Q: BBBuffer<TEST_URC_CAPACITY> = BBBuffer::new();
        let (urc_p, _urc_c) = unsafe { URC_Q.try_split_framed().unwrap() };

        static mut COM_Q: queues::ComQueue = Queue::new();
        let (_com_p, com_c) = unsafe { COM_Q.split() };

        let mut ingress =
            IngressManager::<_, TEST_RX_BUF_LEN, TEST_RES_CAPACITY, TEST_URC_CAPACITY>::new(
                res_p,
                urc_p,
                com_c,
                AtDigester::<UrcTestParser>::new(),
            );

        ingress.write(b"+USORD: 3,266,\"");
        for _ in 0..266 {
            ingress.write(b"s");
        }
        ingress.write(b"\"\r\n");
        ingress.digest();
        let mut grant = res_c.read().unwrap();
        grant.auto_release(true);
        assert_eq!(
            ResponseHeader::from_bytes(grant.as_ref()),
            Err(InternalError::Overflow)
        );
    }
}

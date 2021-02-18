use pyo3::create_exception;
use pyo3::exceptions;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::PyAny;
use std::cmp::Eq;
use std::hash::{Hash, Hasher};

use lightning::ln::peer_handler::{MessageHandler, PeerManager, SocketDescriptor};

use crate::ln::msgs::{PyChannelMessageHandler, PyRoutingMessageHandler};
use crate::logger::LDKLogger;
use crate::primitives::{PyPublicKey, PySecretKey};
use crate::{has_trait_bound, process_python_return};

#[pyclass(name=MessageHandler)]
pub struct PyMessageHandler {
    pub inner: MessageHandler<Box<PyChannelMessageHandler>, Box<PyRoutingMessageHandler>>,
}

#[pyclass(name=SocketDescriptor)]
#[derive(Clone)]
pub struct PySocketDescriptor {
    pub inner: Py<PyAny>,
}

impl PartialEq for PySocketDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl Hash for PySocketDescriptor {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let gil = Python::acquire_gil();
        let py = gil.python();

        // FIXME: Check if this can fail so unwrap is not called.
        self.inner.as_ref(py).hash().unwrap().hash(state);
    }
}

impl Eq for PySocketDescriptor {}

// FIXME: This should be a single exception with associated data
// creating multiple for now until we can create more miningful exceptions.
create_exception!(peer_handler, PeerHandleError, pyo3::exceptions::PyException);
create_exception!(peer_handler, PeerHandleErrorNoReconnect, PeerHandleError);
create_exception!(peer_handler, PeerHandleErrorReconnect, PeerHandleError);

#[pymethods]
impl PySocketDescriptor {
    #[new]
    fn new(socket_descriptor: Py<PyAny>) -> PyResult<Self> {
        if has_trait_bound(&socket_descriptor, vec!["send_data", "disconnect_socket"]) {
            Ok(PySocketDescriptor {
                inner: socket_descriptor,
            })
        } else {
            Err(exceptions::PyTypeError::new_err(format!(
                "Not all required methods are implemented by SocketDescriptor"
            )))
        }
    }

    fn _send_data(&self, data: &[u8], resume_read: bool) -> PyResult<usize> {
        Python::with_gil(|py| {
            let py_socket_desc = self.inner.as_ref(py);
            process_python_return(py_socket_desc.call_method1("send_data", (data, resume_read)))
        })
    }

    fn _disconnect_socket(&self) -> PyResult<()> {
        Python::with_gil(|py| {
            let py_socket_desc = self.inner.as_ref(py);
            match py_socket_desc.call_method0("disconnect_socket") {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        })
    }
}

impl SocketDescriptor for PySocketDescriptor {
    fn send_data(&mut self, data: &[u8], resume_read: bool) -> usize {
        self._send_data(data, resume_read).unwrap()
    }

    fn disconnect_socket(&mut self) {
        self._disconnect_socket().unwrap()
    }
}

#[pyclass(name=PeerManager)]
pub struct PyPeerManager {
    pub inner: PeerManager<
        PySocketDescriptor,
        Box<PyChannelMessageHandler>,
        Box<PyRoutingMessageHandler>,
        Box<LDKLogger>,
    >,
}

#[pymethods]
impl PyPeerManager {
    #[new]
    pub fn new(
        chan_handler: PyChannelMessageHandler,
        route_handler: PyRoutingMessageHandler,
        our_node_secret: PySecretKey,
        ephemeral_random_data: [u8; 32],
        logger: LDKLogger,
    ) -> Self {
        let message_handler = MessageHandler {
            chan_handler: Box::new(chan_handler),
            route_handler: Box::new(route_handler),
        };

        PyPeerManager {
            inner: PeerManager::new(
                message_handler,
                our_node_secret.inner,
                &ephemeral_random_data,
                Box::new(logger),
            ),
        }
    }

    pub fn get_peer_node_ids(&self) -> Vec<PyPublicKey> {
        let mut foreign_node_ids = vec![];
        for node_id in self.inner.get_peer_node_ids().into_iter() {
            foreign_node_ids.push(PyPublicKey { inner: node_id })
        }
        foreign_node_ids
    }

    pub fn new_outbound_connection(
        &self,
        their_node_id: PyPublicKey,
        descriptor: PySocketDescriptor,
        py: Python,
    ) -> PyResult<Py<PyBytes>> {
        match self
            .inner
            .new_outbound_connection(their_node_id.inner, descriptor)
        {
            Ok(x) => Ok(PyBytes::new(py, &x).into()),
            Err(e) => {
                if e.no_connection_possible {
                    Err(PeerHandleErrorNoReconnect::new_err(""))
                } else {
                    Err(PeerHandleErrorReconnect::new_err(""))
                }
            }
        }
    }

    pub fn new_inbound_connection(&self, descriptor: PySocketDescriptor) -> PyResult<()> {
        match self.inner.new_inbound_connection(descriptor) {
            Ok(_) => Ok(()),
            Err(e) => {
                if e.no_connection_possible {
                    Err(PeerHandleErrorNoReconnect::new_err(""))
                } else {
                    Err(PeerHandleErrorReconnect::new_err(""))
                }
            }
        }
    }

    pub fn write_buffer_space_avail(&self, descriptor: &mut PySocketDescriptor) -> PyResult<()> {
        match self.inner.write_buffer_space_avail(descriptor) {
            Ok(_) => Ok(()),
            Err(e) => {
                if e.no_connection_possible {
                    Err(PeerHandleErrorNoReconnect::new_err(""))
                } else {
                    Err(PeerHandleErrorReconnect::new_err(""))
                }
            }
        }
    }

    pub fn read_event(
        &self,
        peer_descriptor: &mut PySocketDescriptor,
        data: &[u8],
    ) -> PyResult<bool> {
        match self.inner.read_event(peer_descriptor, data) {
            Ok(x) => Ok(x),
            Err(e) => {
                if e.no_connection_possible {
                    Err(PeerHandleErrorNoReconnect::new_err(""))
                } else {
                    Err(PeerHandleErrorReconnect::new_err(""))
                }
            }
        }
    }

    pub fn process_events(&self) {
        // This method can panic
        self.inner.process_events()
    }

    pub fn socket_disconnected(&self, descriptor: PySocketDescriptor) {
        // This method can panic
        self.inner.socket_disconnected(&descriptor)
    }

    pub fn timer_tick_occured(&self) {
        self.inner.timer_tick_occured()
    }
}

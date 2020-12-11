use pyo3::create_exception;
use pyo3::prelude::*;

use lightning::util::errors as E;

// Generic API error. Other API errors inherint from this one
create_exception!(errors, APIError, pyo3::exceptions::PyException);

create_exception!(errors, APIMisuseError, APIError);
create_exception!(errors, FeeRateTooHigh, APIError);
create_exception!(errors, RouteError, APIError);
create_exception!(errors, ChannelUnavailable, APIError);
create_exception!(errors, MonitorUpdateFailed, APIError);

pub fn match_api_error(e: E::APIError) -> PyErr {
    match e {
        E::APIError::APIMisuseError { err } => APIMisuseError::new_err(format!("{:?}", e)),
        E::APIError::FeeRateTooHigh { err, feerate } => FeeRateTooHigh::new_err(format!("{:?}", e)),
        E::APIError::RouteError { err } => RouteError::new_err(format!("{:?}", e)),
        E::APIError::ChannelUnavailable { err } => ChannelUnavailable::new_err(format!("{:?}", e)),
        E::APIError::MonitorUpdateFailed => MonitorUpdateFailed::new_err(format!("{:?}", e)),
    }
}

// #[pyclass(name=APIError)]
// pub struct PyAPIError {
//     inner: APIError,
// }

// #[pymethods]
// impl PyAPIError {
//     #[staticmethod]
//     fn api_missuse_error(err: String) -> Self {
//         PyAPIError {
//             inner: APIError::APIMisuseError { err },
//         }
//     }

//     #[staticmethod]
//     fn fee_rate_too_high(err: String, feerate: u32) -> Self {
//         PyAPIError {
//             inner: APIError::FeeRateTooHigh { err, feerate },
//         }
//     }

//     #[staticmethod]
//     fn route_error(err: &'static str) -> Self {
//         PyAPIError {
//             inner: APIError::RouteError { err },
//         }
//     }

//     #[staticmethod]
//     fn channel_unavailable(err: String) -> Self {
//         PyAPIError {
//             inner: APIError::ChannelUnavailable { err },
//         }
//     }

//     #[staticmethod]
//     fn monitor_update_fail() -> Self {
//         PyAPIError {
//             inner: APIError::MonitorUpdateFailed,
//         }
//     }
// }

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

pub fn match_api_error(e: &E::APIError) -> PyErr {
    match e {
        E::APIError::APIMisuseError { .. } => APIMisuseError::new_err(format!("{:?}", &e)),
        E::APIError::FeeRateTooHigh { .. } => FeeRateTooHigh::new_err(format!("{:?}", &e)),
        E::APIError::RouteError { .. } => RouteError::new_err(format!("{:?}", &e)),
        E::APIError::ChannelUnavailable { .. } => ChannelUnavailable::new_err(format!("{:?}", &e)),
        E::APIError::MonitorUpdateFailed => MonitorUpdateFailed::new_err(format!("{:?}", &e)),
    }
}

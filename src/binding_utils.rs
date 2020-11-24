use std;

use pyo3::exceptions;
use pyo3::prelude::*;

pub fn process_python_return<'a, T: FromPyObject<'a>>(
    pyresult: PyResult<&'a PyAny>,
) -> Result<T, PyErr> {
    match pyresult {
        Ok(x) => {
            let inner: Option<T> = x.extract()?;
            match inner {
                Some(x) => Ok(x),
                None => Err(exceptions::PyTypeError::new_err(format!(
                    "Expected a return of type {} from the Python binded method, recieved {}",
                    std::any::type_name::<T>(),
                    x
                ))),
            }
        }
        Err(e) => Err(e),
    }
}

// Failed attempt to bing the whole Python call, may go back to it down the line.

// pub fn python_call<'a, T: FromPyObject<'a>>(
//     pyobject: &'a PyAny,
//     method_name: &str,
//     args: impl IntoPy<Py<PyTuple>>,
// ) -> Result<T, PyErr> {
//     match pyobject.call_method1(method_name, args) {
//         Ok(x) => {
//             let inner: Option<T> = x.extract()?;
//             match inner {
//                 Some(x) => Ok(x),
//                 None => Err(exceptions::PyTypeError::new_err(format!(
//                     "Expected a return of type {} from the Python binded method, recieved {}",
//                     std::any::type_name::<T>(),
//                     x
//                 ))),
//             }
//         }
//         Err(e) => Err(e),
//     }
// }

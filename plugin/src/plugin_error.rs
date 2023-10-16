use std::{fmt::Display, error};


#[derive(Debug, Clone)]
pub struct PluginError {
    msg: String,
}

impl PluginError {
    pub fn new(msg: String) -> Self {
        PluginError { msg }
    }
} 

impl Display for PluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Plugin error {}", self.msg)
    }
}

impl error::Error for PluginError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }

    fn description(&self) -> &str {
        "description() is deprecated; use Display"
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        self.source()
    }
}
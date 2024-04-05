use solana_geyser_plugin_interface::geyser_plugin_interface::GeyserPlugin;


pub mod config;

#[derive(Debug, Default)]
pub struct Plugin {
}

impl GeyserPlugin for Plugin {
    fn name(&self) -> &'static str {
        "geyser_empty_plugin"
    }

    fn on_load(
        &mut self,
        _config_file: &str,
    ) -> solana_geyser_plugin_interface::geyser_plugin_interface::Result<()> {
        Ok(())
    }

    fn on_unload(&mut self) {}
}

#[no_mangle]
#[allow(improper_ctypes_definitions)]
pub unsafe extern "C" fn _create_plugin() -> *mut dyn GeyserPlugin {
    let plugin = Plugin::default();
    let plugin: Box<dyn GeyserPlugin> = Box::new(plugin);
    Box::into_raw(plugin)
}

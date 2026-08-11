// Verhindert ein zweites Konsolenfenster im Release-Build auf Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    openom_lib::run()
}

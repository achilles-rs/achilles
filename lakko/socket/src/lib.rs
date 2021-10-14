#![crate_type = "staticlib"]

pub mod hostinet;

#[no_mangle]
pub fn place_holder(input: i32) -> i32 {
    let t = hostinet::ioctl(input);
    t * 2
}
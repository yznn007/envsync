//! 桌面应用二进制入口。

fn main() {
    envsync_desktop::run().expect("启动 EnvSync 桌面壳失败");
}

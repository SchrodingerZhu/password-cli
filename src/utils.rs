use botan::{Privkey, Pubkey};

static MY_PRIVATE : &'static str = include_str!("/code/keys/keeper_pri.pem");
pub static SERVER_PUBLIC: &'static str = include_str!("/code/server/server.pem.pub");
pub static SERVER : &'static str = "http://118.31.59.227:14514";

#[inline(always)]
pub(crate) fn get_private(password: &str) -> Option<Privkey> {
    Privkey::load_encrypted_pem(MY_PRIVATE, password).ok()
}

#[inline(always)]
pub(crate) fn get_pubkey() -> Pubkey {
    Pubkey::load_pem(SERVER_PUBLIC).unwrap_or_else(failed_with("invalid public key"))
}


#[inline(always)]
pub fn failed_with<T  : 'static, U>(message: &str) -> Box<dyn FnOnce(T) -> U>{
    let message = String::from(message);
    Box::new(move |_| {
        eprintln!("[ERROR] {}", message);
        std::process::exit(1)
    })
}

#[inline(always)]
pub fn output_res(res: &[String]) {
    if res.is_empty() {
        eprintln!("[ERROR] empty reply");
        std::process::exit(1)
    } else {
        for i in res {
            println!("{}", i);
        }
    }
}

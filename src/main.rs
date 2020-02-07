mod client;
mod utils;
pub use utils::*;
use structopt::*;
use crate::{failed_with, output_res};
use crate::client::{query, Insertion};
use std::io::{stdin, Write};

#[derive(StructOpt, Debug, Eq, PartialEq)]
#[structopt(about = "the password keeper")]
pub(crate) enum Opt {
    #[structopt(about = "add a new password")]
    Add {
        #[structopt(short)]
        name: String,
    },
    #[structopt(about = "get the password")]
    Fetch {
        #[structopt(short)]
        name: String,
    },
    #[structopt(about = "remove the password")]
    Remove {
        #[structopt(short)]
        name: String,
    },
    #[structopt(about = "list all password names")]
    List,

    #[structopt(about = "generate a new password and store")]
    GenPassword {
        #[structopt(short)]
        name: String
    },

    #[structopt(about = "add secure file")]
    AddFile {
        #[structopt(short)]
        name: String,
        #[structopt(short)]
        path: String
    },
}

fn main() {
    use Opt::*;
    let opt = Opt::from_args();
    let rng = botan::RandomNumberGenerator::new()
        .unwrap_or_else(failed_with("unable to initialize random generator"));
    let private_key = rpassword::read_password_from_tty(Some("password: "))
        .ok().and_then(|x|get_private(x.as_str()))
        .unwrap_or_else(|| {
            eprintln!("[ERROR] failed to decode the private key");
            std::process::exit(1);
        });
    match opt {
        List => {
            let mut nonsense = [0; 16];
            rng.fill(&mut nonsense)
                .unwrap_or_else(failed_with("unable to generate nonsense"));
            let res = query("list".to_string(), botan::base64_encode(&nonsense).unwrap(),
                &private_key, &rng);
            output_res(res.as_slice());
        }
        Add { name } => {
            let password = rpassword::read_password_from_tty(Some("content: "))
                .unwrap_or_else(failed_with("unable to get content"));
            let content = Insertion {
                name,
                content: password
            };
            let res = query("add".to_string(),
                            content.to_json(), &private_key, &rng);
            output_res(res.as_slice());
        },
        Fetch { name } => {
            let res = query("fetch".to_string(), name, &private_key, &rng);
            output_res(res.as_slice());
        },
        Remove {name} => {
            let mut buf = String::new();
            print!("Re-type the name to confirm: ");
            std::io::stdout().flush().unwrap();
            stdin().read_line(&mut buf).unwrap_or_else(failed_with("unable to readline"));
            if buf.trim() == name {
                let res = query("delete".to_string(), name, &private_key, &rng);
                output_res(res.as_slice());
            }
        },
        GenPassword { name } => {
            let res = query("generate".to_string(), name, &private_key, &rng);
            output_res(res.as_slice());
        },
        AddFile { name, path } => {
            let file = std::fs::read_to_string(path)
                .unwrap_or_else(failed_with("unable to read file"));
            let content = Insertion {
                name,
                content: file
            };
            let res = query("add".to_string(),
                            content.to_json(), &private_key, &rng);
            output_res(res.as_slice());
        }
    }
}

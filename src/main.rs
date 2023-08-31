#![feature(array_zip)]
#![feature(slice_flatten)]
#![deny(warnings)]
mod adaptor;
pub mod circuits;
pub mod host;
pub mod utils;
pub mod proof;

use clap::{arg, value_parser, App, Arg, ArgMatches};
use std::path::PathBuf;
use crate::proof::{gen_host_proof, OpType};


#[derive(clap::Parser)]
struct ArgOpName {
    #[clap(arg_enum)]
    t: OpType,
}

fn output_folder<'a>() -> Arg<'a> {
    arg!(-o --output<OUTPUT_FOLDER>... "output file folder that contains all setup and proof results")
        .max_values(1)
        .value_parser(value_parser!(PathBuf))
}

fn parse_output_folder(matches: &ArgMatches) -> PathBuf {
    matches
        .get_one::<PathBuf>("output")
        .expect("input file is required")
        .clone()
}

fn input_file<'a>() -> Arg<'a> {
    arg!(-i --input<INPUT_FILES>... "Input file that contains all host function call")
        .max_values(1)
        .value_parser(value_parser!(PathBuf))
}

fn parse_input_file(matches: &ArgMatches) -> PathBuf {
    matches
        .get_one::<PathBuf>("input")
        .expect("input file is required")
        .clone()
}

fn opname<'a>() -> Arg<'a> {
    arg!(-n --opname<OP_NAME>... "Operation name")
        .max_values(1)
        .value_parser(value_parser!(OpType))
}

fn parse_opname(matches: &ArgMatches) -> OpType {
    matches
        .get_one::<OpType>("opname")
        .expect("opname is required")
        .clone()
}

#[allow(clippy::many_single_char_names)]
fn main() {
    let clap_app = App::new("hostcircuit")
        .arg(input_file())
        .arg(output_folder())
        .arg(opname());

    let matches = clap_app.get_matches();
    let input_file = parse_input_file(&matches);
    let cache_folder = parse_output_folder(&matches);
    let opname = parse_opname(&matches);

    // ANCHOR: test-circuit
    // The number of rows in our circuit cannot exceed 2^k. Since our example
    // circuit is very small, we can pick a very small value here.
    let k = 22;

    gen_host_proof("host", k, cache_folder, input_file, opname);

}

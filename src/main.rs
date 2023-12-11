use std::{collections::HashMap, env::args, io::stdin, process::exit, str::FromStr};

use abnf::{self, rulelist};
use abnf_to_mtsx::{rulelist_to_mtsx, Color, DisplayMeta};

const MT_MANAGER_VERSION: &str = "v2.14.3-beta@23120971";

macro_rules! err {
    ($($t:tt)*) => {
        eprint!("\x1b[1;91m{}\x1b[0m", format_args!($($t)*));
    };
}
macro_rules! warn {
    ($($t:tt)*) => {
        eprint!("\x1b[1;93m{}\x1b[0m", format_args!($($t)*));
    };
}

fn help() {
    print!(
        "\
        {}@{}\n\
        \n\
        Author: {}\n\
        Repo: {}\n\
        \n\
        {}\n\
        It is not recommended to abuse ABNF,\n\
        otherwise dynamic highlighting performance may be very poor!\n\
        \n\
        input from stdin, output to stdout.\n\
        \n\
        MT-Manager version: {}\n\
        \n\
        from line begin, commands:\n\
        \x20 `//!BEGIN`: abnf start\n\
        \x20 `//!END`: abnf stop\n\
        \x20 `//!CODE`: abnf insertion point\n\
        \x20 `//!COLOR`: color defined insertion point\n\
        \x20 `//!NOOPT`: no running optimization\n\
        \x20 `//!COLORDEF name=...`: define color of name\n\
        \n\
        color formats:\n\
        \x20 `\"colorname\"`: use defined color\n\
        \x20 `#(#aaaaaa, #bbbbbb)`: use define anon color\n\
        ",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_AUTHORS"),
        env!("CARGO_PKG_REPOSITORY"),
        env!("CARGO_PKG_DESCRIPTION"),
        MT_MANAGER_VERSION,
    );
}

fn main() {
    if args().len() != 1 {
        help();
        exit(1)
    }
    let mut lines = Vec::new();
    for line in stdin().lines() {
        lines.push(line.unwrap());
    }
    let mut abnf_src = String::new();
    let mut reading_abnf = false;
    let mut color_def_insp = None;
    let mut code_insp = None;
    let mut colors_table = HashMap::new();
    let mut do_opt = true;
    const COLORDEF_PREFIX: &str = "//!COLORDEF ";
    for (num, line) in lines.iter().enumerate() {
        let line = line.trim();
        if line.starts_with(COLORDEF_PREFIX) {
            let body = line.strip_prefix(COLORDEF_PREFIX).unwrap();
            let Some((name, color_str)) = body.split_once('=') else {
                err!("Error: Color value not found. ({body})\n");
                exit(2)
            };
            let Ok(color) = Color::from_str(color_str) else {
                err!("Error: Color invalid value. ({name}={color_str})\n");
                exit(2)
            };
            if let Some(color) = colors_table.insert(name, color) {
                warn!("Warn: Repeat define color, old:({name}={color})\n");
            }
            continue;
        }
        match line {
            "//!BEGIN" => reading_abnf = true,
            "//!END" => reading_abnf = false,
            "//!CODE" => code_insp = num.into(),
            "//!COLOR" => color_def_insp = num.into(),
            "//!NOOPT" => do_opt = false,
            abnf_line if reading_abnf => {
                abnf_src.push_str(abnf_line);
                abnf_src.push('\n');
            },
            _ => (),
        }
    }
    let Some(color_def_insp) = color_def_insp else {
        err!("Error: Color defined insertion point not found!\n");
        exit(2)
    };
    let Some(code_insp) = code_insp else {
        err!("Error: Code insertion point not found!\n");
        exit(2)
    };
    let rulelist = match rulelist(&abnf_src) {
        Ok(rulelist) => rulelist,
        Err(e) => {
            err!("ABNF::ParseError:\n{}", e);
            exit(2)
        },
    };
    let mut meta = rulelist_to_mtsx(&rulelist);
    if do_opt { meta.optimization() }
    meta.set_colors(
        &mut colors_table,
        |res| {
            if let Ok(Some(color)) = res {
                panic!("终止, 已经拥有颜色 {:?}", color)
            }
        },
        |_| (),
    );
    let mut display_meta = DisplayMeta::new();
    meta.display(&mut display_meta);
    let mt_defines = display_meta.str();
    let mut iter = lines.iter().enumerate();
    'a: while let Some((num, line)) = iter.next() {
        // skip
        match line.trim() {
            "//!BEGIN" => loop {
                if iter.next().unwrap().1.trim() == "//!END" {
                    continue 'a;
                }
            },
            "//!NOOPT" => continue,
            s if s.starts_with(COLORDEF_PREFIX) => continue,
            _ => (),
        }
        let b_line = line.trim_start();
        let indent = &line[..line.len() - b_line.len()];
        if num == color_def_insp {
            for (name, value) in display_meta.color_list() {
                println!("{indent}{name:?}, {value},")
            }
        } else if num == code_insp {
            for code in mt_defines.lines() {
                println!("{indent}{code}")
            }
        } else {
            println!("{line}");
        }
    }
    for (name, value) in colors_table {
        warn!("Warn: Unused color ({name}={value})\n");
    }
}

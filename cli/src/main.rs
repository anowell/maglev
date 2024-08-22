use anyhow::{Context, Result};
use askama::Template;
use clap::{Parser, Subcommand};
use heck::ToSnakeCase;
use log::LevelFilter;
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::{env, fs};

pub mod filters;

#[derive(Parser)]
#[command(name = "maglev", about = "Speed up API development")]
struct Cli {
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbosity: u8,

    #[arg(long)]
    dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(alias = "g")]
    Generate {
        #[arg(short = 'f', long = "force", global = true, default_value_t = false)]
        force: bool,

        #[command(subcommand)]
        generate_type: GenerateType,
    },
}

#[derive(Subcommand)]
enum GenerateType {
    Job {
        #[arg(value_name = "job_name")]
        name: String,

        #[arg(long = "state", default_value = "Context")]
        state_path: String,
    },
    // Crud {
    //     #[arg(value_name = "crud_name")]
    //     name: String,
    // },
}

#[derive(Template)]
#[template(path = "job.rst", escape = "none")]
struct JobTemplate<'a> {
    name: &'a str,
    state_path: &'a str,
    state_type: &'a str,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Set up logging based on verbosity
    let log_level = match cli.verbosity {
        0 => LevelFilter::Info,
        1 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };
    TermLogger::init(
        log_level,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap();

    let dir = match cli.dir {
        Some(dir) => dir,
        None => env::current_dir()?,
    };

    match &cli.command {
        Commands::Generate {
            generate_type,
            force,
        } => match generate_type {
            GenerateType::Job { name, state_path } => {
                let state_type = state_path.split("::").last().unwrap();
                let template = JobTemplate {
                    name,
                    state_path,
                    state_type,
                };
                let path = dir.join(format!("src/jobs/{}.rs", name.to_snake_case()));
                generate_file(&path, template, *force)?;
                import_mod(path)?;
            } // GenerateType::Crud { name } => todo!(),
        },
    }
    Ok(())
}

fn generate_file<P: AsRef<Path>>(path: P, template: impl Template, force: bool) -> Result<()> {
    let path = path.as_ref();
    let content = template.render().context("rendering template")?;
    log::trace!("{}", content);
    if force || !path.exists() {
        std::fs::write(&path, content)
            .with_context(|| format!("writing file {}", path.display()))?;
        log::info!("Generated {}", path.display());
    } else {
        log::info!("{} already exists. Use --force to replace.", path.display());
    }

    Ok(())
}

fn import_mod<P: AsRef<Path>>(path: P) -> Result<()> {
    let path = path.as_ref();
    let mod_file = path.with_file_name("mod.rs");
    let mod_name = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .context("invalid filename")?;

    let mod_statement = format!("mod {};", mod_name);
    let use_statement = format!("pub use {}::*;", mod_name);

    // Read the content of mod.rs
    let content = fs::read_to_string(&mod_file).unwrap_or_default();

    // Early return if the use statement already exists
    if content.contains(&mod_statement) && content.contains(&use_statement) {
        log::debug!(
            "mod {} already imported in {}",
            mod_name,
            mod_file.display()
        );
        return Ok(());
    }

    // Split lines and classify existing statements
    let mut lines: VecDeque<_> = content.lines().collect();
    let mut insert_idx = 0;

    // Find the appropriate place to insert the new `pub use`
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("pub use")
            || trimmed.starts_with("use")
            || trimmed.starts_with("mod")
        {
            insert_idx = i + 1;
        }
    }

    log::trace!(
        "Inserting module '{}' in {}:{}",
        mod_name,
        mod_file.display(),
        insert_idx
    );

    // Insert the new statement
    lines.insert(insert_idx, mod_statement.as_str());
    lines.insert(insert_idx + 1, use_statement.as_str());

    // Write back to mod.rs
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&mod_file)
        .with_context(|| format!("opening mod.rs at {}", mod_file.display()))?;

    for line in lines {
        writeln!(file, "{}", line)?;
    }

    Ok(())
}

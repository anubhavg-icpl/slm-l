mod cli;
mod detector;
mod llm;
mod patterns;
mod report;
mod scanner;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cli::run().await
}

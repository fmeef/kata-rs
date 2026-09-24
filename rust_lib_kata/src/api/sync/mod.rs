pub fn reqwest_test() -> anyhow::Result<()> {
    reqwest::blocking::get("https://example.com")?;
    Ok(())
}

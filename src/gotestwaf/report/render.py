"""PDF rendering using Playwright (Chromium headless)."""

from __future__ import annotations

from pathlib import Path


async def render_to_pdf(file_to_render_url: str, path_to_result_pdf: str) -> None:
    """Render an HTML file to PDF using headless Chromium via Playwright.

    Args:
        file_to_render_url: URL (file://) to the HTML file.
        path_to_result_pdf: Output path for the PDF file.
    """
    from playwright.async_api import async_playwright

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=[
                "--no-zygote",
                "--no-sandbox",
                "--disable-gpu",
                "--run-all-compositor-stages-before-draw",
            ],
        )

        try:
            page = await browser.new_page()
            await page.goto(file_to_render_url, wait_until="networkidle")

            # Wait for Chart.js and Three.js to render canvases
            await page.wait_for_timeout(3000)
            # Scroll to trigger any lazy rendering
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await page.wait_for_timeout(1000)

            pdf_bytes = await page.pdf(
                print_background=True,
                format="A4",
                margin={"top": "10mm", "bottom": "10mm", "left": "10mm", "right": "10mm"},
            )

            Path(path_to_result_pdf).write_bytes(pdf_bytes)
        finally:
            await browser.close()

from playwright.sync_api import sync_playwright
import time

def run():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.set_viewport_size({"width": 1440, "height": 900})

        print("Navigating to http://localhost:5174/mission-control to clear local storage... wait no, go to home")
        page.goto("http://localhost:5174/app-v2/", wait_until="networkidle")

        # Click Intake
        print("Clicking Intake link")
        page.click("text=Intake")
        page.wait_for_timeout(2000)
        page.screenshot(path="screenshot_intake_split.png", full_page=True)
        print("Saved screenshot_intake_split.png")

        # Try to click the first tile to see the flip
        print("Clicking first tile to trigger flip")
        page.locator("[data-testid^='wizard-assessment-tile-']").first.click()
        page.wait_for_timeout(1000)
        page.screenshot(path="screenshot_intake_flipped.png", full_page=True)
        print("Saved screenshot_intake_flipped.png")

        browser.close()

if __name__ == "__main__":
    run()
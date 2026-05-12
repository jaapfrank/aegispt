from playwright.sync_api import sync_playwright

def run():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.set_viewport_size({"width": 3840, "height": 2160})

        print("Navigating to http://localhost:5174/mission-control")
        page.goto("http://localhost:5174/mission-control", wait_until="networkidle")

        print("Waiting for page to render...")
        page.wait_for_timeout(3000)

        page.screenshot(path="screenshot_mission_control_4k.png", full_page=True)
        print("Saved screenshot_mission_control_4k.png")

        browser.close()

if __name__ == "__main__":
    run()
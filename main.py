import tkinter as tk
from tkinter import scrolledtext, messagebox
from tkinter import ttk  # For dropdown menus
from playwright.sync_api import sync_playwright
from bs4 import BeautifulSoup
import requests
from datetime import datetime
import csv
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Scrape vulnerabilities function
def scrape_vulnerability(url):
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url)
            page.wait_for_load_state('networkidle')  # Wait for network to be idle

            html = page.content()
            soup = BeautifulSoup(html, 'html.parser')

            # advisory_rows = soup.find_all('tr', class_='rowRepeat')

            # vulnerabilities = []
            # for row in advisory_rows:
            #     try:
            #         product_name_elem = row.find('a', class_='ng-binding')
            #         product_name = product_name_elem.text.strip() if product_name_elem else 'Unknown'

            #         severity_elem = row.find('span', class_='ng-binding')
            #         severity = severity_elem.text.strip() if severity_elem else 'Unknown'

            #         cve_elem = row.find('p', class_='ng-scope')
            #         cve_id = cve_elem.get_text(strip=True).split('\n')[0] if cve_elem else 'Unknown'

            #         published_date_elem = row.find_all('td')[3].find('span', class_='ng-binding')
            #         published_date = published_date_elem.text.strip() if published_date_elem else 'Unknown'

            #         version_elem = row.find_all('td')[5].find('span', class_='ng-binding')
            #         version = version_elem.text.strip() if version_elem else 'Unknown'

                    
                    

            # Find all rows with class "rowRepeat"
            rows = soup.find_all('tr', class_='rowRepeat')

            vulnerabilities = []
            for row in rows:
                try:
                    # Access child table
                    child_table = row.find('table')
                    child_rows = child_table.find_all('tr')

                    # First row contains main information
                    product_name = child_rows[0].find('a').text.strip() if child_rows[0].find('a') else 'N/A'
                    severity = child_rows[0].find('span', class_='ng-binding').text.strip() if child_rows[0].find('span', class_='ng-binding') else 'N/A'
                    cve_id = child_rows[0].find('p').find('span', class_='ng-binding').text.strip() if child_rows[0].find('p') and child_rows[0].find('p').find('span', class_='ng-binding') else 'N/A'
                    version = child_rows[0].find('span', class_='ng-binding ng-scope').text.strip() if child_rows[0].find('span', class_='ng-binding ng-scope') else 'N/A'
                    published_date = child_rows[0].find_all('span', class_='ng-binding')[-1].text.strip() if child_rows[0].find_all('span', class_='ng-binding') else 'N/A'

                    # Second row contains additional details
                    child_row = child_rows[1].find('div', class_='colsChildWrap')

                    publication_id = child_row.find('div', class_='childRowCol1').find('p').find('span', class_='ng-binding').text.strip() if child_row.find('div', class_='childRowCol1').find('p') and child_row.find('div', class_='childRowCol1').find('p').find('span', class_='ng-binding') else 'N/A'

                    crow = soup.find('div', class_='childRowCol1')

                    first_published = crow.find('p', string=lambda text: text and 'First Published:' in text)
                    if first_published:
                        first_published = first_published.find_next('span', class_='ng-binding').text.strip()
                    else:
                        first_published = 'N/A'

                    workaround = child_row.find('div', class_='childRowCol2').find('p').find('span', class_='ng-binding').text.strip() if child_row.find('div', class_='childRowCol2').find('p') and child_row.find('div', class_='childRowCol2').find('p').find('span', class_='ng-binding') else 'N/A'

                    summary = child_row.find('div', class_='childRowCol3').find('p').find('span', class_='ng-binding').text.strip() if child_row.find('div', class_='childRowCol3').find('p') and child_row.find('div', class_='childRowCol3').find('p').find('span', class_='ng-binding') else 'N/A'

                
                    
                    if severity.upper() in ['CRITICAL', 'HIGH']:
                        vulnerabilities.append({
                            'Product Name': product_name,
                            'Publication ID': publication_id,
                            'Severity': severity,
                            'CVE ID': cve_id,
                            'Version': version,
                            'Published Date': published_date,
                            'First Published': first_published,
                            'Publication ID': publication_id,
                            'Workaround': workaround,
                            'Summary': summary
                        })
                except Exception as e:
                    print(f"Error parsing row: {e}")
            return vulnerabilities

    except Exception as e:
        messagebox.showerror("Scraping Error", f"An error occurred while scraping: {e}")
    return []

# Validate URL
def is_valid_url(url):
    try:
        result = requests.get(url)
        return result.status_code == 200
    except Exception:
        return False

# Save to CSV function
def save_to_csv(vulnerabilities, filename="vulnerabilities.csv"):
    if vulnerabilities:
        file_exists = os.path.isfile(filename)
        with open(filename, mode='a', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=vulnerabilities[0].keys())
            if not file_exists:
                writer.writeheader()
            writer.writerows(vulnerabilities)
        print(f"Vulnerabilities saved to {filename}")
    else:
        print("No vulnerabilities to save.")




# Email sending function
def send_email(vulnerabilities):
    # Email details
    sender_email = ""
    receiver_email = "95devmondal@gmail.com"
    subject = "Critical and High Severity Vulnerabilities Report"
    password = ""  # account password

    # Compose email content
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject

    # Create the email body
    body = "The following vulnerabilities were found:\n\n"
    for vul in vulnerabilities:
        body += f"Product Name: {vul['Product Name']}\n"
        body += f"Severity: {vul['Severity']}\n"
        body += f"CVE ID: {vul['CVE ID']}\n"
        body += f"Published Date: {vul['Published Date']}\n"
        body += f"Version: {vul['Version']}\n"
        body += "-"*40 + "\n"

    # Attach the body to the email
    message.attach(MIMEText(body, "plain"))

    try:
        # Establish a connection to the SMTP server using TLS
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()  # Enable TLS
            server.login(sender_email, password)  # Login using the app password
            server.sendmail(sender_email, receiver_email, message.as_string())  # Send the email
        print("Email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")







# GUI Application
class VulnerabilityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Vulnerability Scraping Tool")

        self.rescrape_interval = tk.IntVar(value=5)  # Default rescrape interval to 5 minutes
        self.remaining_time = tk.IntVar(value=0)
        self.timer_running = False  # Timer running flag
        self.timer_id = None  # Timer reference

        # URL input
        self.url_entry = tk.Entry(root, width=80)
        self.url_entry.pack(pady=10)
        self.url_entry.insert(0, "https://sec.cloudapps.cisco.com/security/center/publicationListing.x")  # Default URL

        # Online status label
        self.status_label = tk.Label(root, text="Checking online status...", fg="black")
        self.status_label.pack(pady=5)

        # Last update label
        self.last_update_label = tk.Label(root, text="Last Updated: N/A")
        self.last_update_label.pack(pady=5)

        # Timer display
        self.timer_label = tk.Label(root, text="Next rescan in: 00:00")
        self.timer_label.pack(pady=5)

        # Interval setting input
        self.interval_label = tk.Label(root, text="Set rescrape interval (in minutes):")
        self.interval_label.pack(pady=5)
        self.interval_spinbox = ttk.Spinbox(root, from_=1, to=60, textvariable=self.rescrape_interval, width=10)
        self.interval_spinbox.pack(pady=5)

        # Scrape button
        self.scrape_button = tk.Button(root, text="Scrape Vulnerabilities", command=self.scrape)
        self.scrape_button.pack(pady=5)

        # Log display
        self.log_display = scrolledtext.ScrolledText(root, width=100, height=30)
        self.log_display.pack(pady=10)

        # Initialize timer
        self.schedule_scrape()

    def scrape(self):
        url = self.url_entry.get()
        if not is_valid_url(url):
            messagebox.showwarning("Invalid URL", "The provided URL is not valid or offline.")
            self.status_label.config(text="Offline", fg="red")
            return

        self.status_label.config(text="Online", fg="green")

        vulnerabilities = scrape_vulnerability(url)
        self.log_display.delete(1.0, tk.END)

        if vulnerabilities:
            for vul in vulnerabilities:
                self.log_display.insert(tk.END, f"Product Name: {vul['Product Name']}\n")
                self.log_display.insert(tk.END, f"First Published: {vul['First Published']}\n")
                self.log_display.insert(tk.END, f"Severity: {vul['Severity']}\n")
                self.log_display.insert(tk.END, f"CVE ID: {vul['CVE ID']}\n")
                self.log_display.insert(tk.END, f"Version: {vul['Version']}\n")
                self.log_display.insert(tk.END, f"Published Date: {vul['Published Date']}\n")
                self.log_display.insert(tk.END, f"Publication ID: {vul['Publication ID']}\n")
                self.log_display.insert(tk.END, f"Workaround: {vul['Workaround']}\n")
                self.log_display.insert(tk.END, f"Summary: {vul['Summary']}\n")
                self.log_display.insert(tk.END, "-"*40 + "\n")

            # Save vulnerabilities to CSV
            save_to_csv(vulnerabilities)

            # Send email with the vulnerabilities
            send_email(vulnerabilities)

            # Update last update time
            last_update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.last_update_label.config(text=f"Last Updated: {last_update_time}")
        else:
            self.log_display.insert(tk.END, "No critical or high severity vulnerabilities found.\n")

        # Schedule next scrape
        self.schedule_scrape()

    def schedule_scrape(self):
        # Cancel any previous timer if running
        if self.timer_id:
            self.root.after_cancel(self.timer_id)

        # Get the user-defined interval and reset the timer
        interval_minutes = self.rescrape_interval.get()
        interval_seconds = interval_minutes * 60
        self.remaining_time.set(interval_seconds)
        
        self.update_timer()
        self.timer_running = True

    def update_timer(self):
        remaining_seconds = self.remaining_time.get()

        if remaining_seconds > 0:
            minutes, seconds = divmod(remaining_seconds, 60)
            self.timer_label.config(text=f"Next rescan in: {minutes:02}:{seconds:02}")
            self.remaining_time.set(remaining_seconds - 1)
            self.timer_id = self.root.after(1000, self.update_timer)  # Update every second
        else:
            self.scrape()  # Perform the scraping when time runs out

if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityApp(root)
    root.mainloop()

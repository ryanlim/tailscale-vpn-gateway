# NordVPN Web Interface

This project provides a simple web interface to manage NordVPN on a Linux server. Through this interface, you can select countries and establish a VPN connection or disconnect from the VPN. The available countries are fetched directly from the NordVPN API.

## Table of contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
    - [Running the Project with Python](#running-the-project-for-testing-with-python)
    - [Running the Project with Gunicorn and a Systemd Service](#running-the-project-with-gunicorn-and-a-systemd-service)
- [Features and Limitations](#features-and-limitations)
- [Notes](#notes)

## Prerequisites

- **NordVPN** must be pre-installed. You can find installation instructions for NordVPN on various Linux distributions [here](https://support.nordvpn.com/hc/en-us/articles/20196094470929-Installing-NordVPN-on-Linux-distributions).
- **Python 3.x** must be installed.

## Installation

1. #### Clone the repository:

    ```bash
    git clone https://your-repo-link
    cd your-repo-directory
    ```
2. #### Install dependencies:

    Ensure all required Python packages are installed by running the following command:

    ```bash
    pip install -r requirements.txt
    ```
## Usage

1. #### Running the Project for Testing with Python

    To quickly test the web interface, you can run the project directly using Python:

    ```bash
    python app.py
    ```
   
    The web interface will be accessible at http://localhost:80.

2. #### Running the Project with Gunicorn and a Systemd Service**

    For a production-like environment, it's recommended to use Gunicorn along with a Systemd service.

   1. **Install Gunicorn:**

      If Gunicorn is not already installed, you can install it with pip:

       ```bash
       pip install gunicorn
       ```

   2. **Run Gunicorn:**

      For a quick test, you can start Gunicorn directly:

      ```bash
      gunicorn -w 4 -b 0.0.0.0:80 app:app
      ```

   3. **Set up a Systemd service:**

      Create a service file at '/etc/systemd/system/vpn-web.service':

      ```ini
      [Unit]
      Description=Gunicorn instance to serve VPN Web Service
      After=network.target
    
      [Service]
      User=yourusername
      Group=www-data
      WorkingDirectory=/path/to/your/project
      ExecStart=/path/to/your/venv/bin/gunicorn -w 4 -b 0.0.0.0:80 app:app
    
      [Install]
      WantedBy=multi-user.target
      ```

      Replace 'yourusername' with your actual username and adjust the paths to your project and virtual environment accordingly.

   4. **Start and enable the service:**

      Start the service and enable it to start automatically at boot:

      ```bash
      sudo systemctl start vpn-web
      sudo systemctl enable vpn-web
      ```

## Features and Limitations

- **Country Selection:** The selection is done through a dropdown menu showing all available countries supported by the NordVPN API.
- **Connect/Disconnect:** The interface allows you to connect to or disconnect from a VPN in a selected country.
- **Language:** The interface is currently available only in German.
- **Server Selection:** Selecting a specific server within a country is not currently supported.

## Notes

- This project is intended for users who need a simple way to manage NordVPN via a web interface on a Linux server.
- The project is in an early development stage, and additional features may be added in the future.



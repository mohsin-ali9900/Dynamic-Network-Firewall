# Network Packet Capture and Filtering Application

## Overview
This project is a comprehensive network packet capture and filtering application developed in Python. It allows users to monitor and control network traffic in real-time by capturing packets, applying user-defined filtering rules, logging the traffic, and visualizing the packet data. The primary purpose of this project is to enhance network security and provide users with insights into their network activity.

## Features
- Real-time packet capture using the `pydivert` library.
- Customizable filtering rules based on IP addresses, ports, protocols, and specific programs.
- Detailed logging of captured packets with the option to export logs to a CSV file.
- Real-time statistics on total, blocked, and allowed packets.
- Live chart visualization of network traffic using `matplotlib`.
- User-friendly graphical interface built with `tkinter`.

## Technologies and Tools Used
- ``Python``: Main programming language.
- ``pydivert``: Library for capturing and filtering network packets.
- ``psutil``: Used to match packets to specific programs.
- ``tkinter``: GUI toolkit for building the graphical user interface.
- ``matplotlib``: Library for plotting live charts to visualize packet traffic.
- ``csv``: Module for exporting packet logs to a CSV file.
- ``threading``: Used to ensure smooth real-time packet capture and GUI operations.

## Prerequisites
Before running this project, ensure you have the following installed on your system:
- Python 3.x
- pip (Python package installer)

## Installation
1. **Clone the Repository**:
   ```sh
   git clone https://github.com/yourusername/packet-capture-filtering.git

2. **Install Depandencies**:
    ```sh 
    pip install -r requirements.txt

## Usage
1. **Run the Application**:
    ```sh 
    python main.py

2. **Define Filtering Rules**:
    - Open the application and navigate to the rules section.

    - Add rules based on IP address, port, protocol, or specific program.

    - Save the rules.

3. **Start Packet Capture**:
    - Click on the "Start Capture" button to begin capturing and filtering packets in real-time.

4. **View Logs and Statistics**:
    - Monitor real-time statistics on total, blocked, and allowed packets.
    
    - View detailed logs of captured packets.

5. **Visualize Traffic**:
    - Check the live chart to visualize network traffic over time.

6. **Export Logs to CSV**:
    - Export the packet logs to a CSV file for further analysis.

## Contributing
We welcome contributions! If you have ideas for improvements or new features, please open an issue or submit a pull request. Follow these steps to contribute:

1. Fork the repository.

2. Create a new branch (``git checkout -b feature-branch``).

3. Commit your changes (``git commit -m 'Add new feature'``).

4. Push to the branch (``git push origin feature-branch``).

5. Open a pull request.

## Future Enhancements
- Implement deep packet inspection (DPI) for more detailed analysis.

- Integrate machine learning for anomaly detection.

- Enhance the GUI with more customizable options and advanced filters.

- Extend compatibility to other operating systems like macOS and Linux.

- Add real-time alerting for suspicious activities.

## Contact
If you have any questions or need further assistance, please contact us at ``mohsin99alii@gmail.com``



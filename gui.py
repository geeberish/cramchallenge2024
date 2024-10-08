from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QVBoxLayout, QFileDialog, QHBoxLayout, QListWidget, QStackedWidget, QScrollArea
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QPalette, QColor, QFont, QIcon
import shutil
import sys
import os
import csv
import matplotlib.pyplot as plt
import hashlib  # For hashing the CSV file
from average import *
import average as avg

class SystemEvaluationApp(QWidget):
    def __init__(self):
        super().__init__()

        # Create the submissions folder if it doesn't exist
        self.submissions_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'submissions')
        if not os.path.exists(self.submissions_folder):
            os.makedirs(self.submissions_folder)

        # Initialize the submitted_files list before calling any methods that use it
        self.submitted_files = self.load_submissions()  # Load previously submitted files
        app_icon = QIcon('files/logo.png')  # Replace with the path to your icon file

        # Set window title and size
        self.setWindowIcon(app_icon)

        # Set window title and size
        self.setWindowTitle("ACRES")
        self.showMaximized()  # Set to fullscreen windowed (borderless window)

        # Set background color to dark gray and text color to white
        palette = self.palette()
        palette.setColor(QPalette.Window, QColor(45, 45, 45))  # Dark gray
        palette.setColor(QPalette.WindowText, QColor(255, 255, 255))  # White text
        self.setPalette(palette)

        # Set font to Helvetica at point 12
        self.font = QFont("Helvetica", 12)
        self.setFont(self.font)

        # Set up a stacked widget to switch between the main and previous submissions view
        self.stacked_widget = QStackedWidget(self)
        

        # Create the main submission view
        self.main_view = self.create_main_view()
        self.stacked_widget.addWidget(self.main_view)

        self.previous_submissions_view = self.create_previous_submissions_view()
        self.stacked_widget.addWidget(self.previous_submissions_view)  # Add the previous submissions view

        # Set the main layout for the app
        layout = QVBoxLayout(self)
        layout.addWidget(self.stacked_widget)

        # Variable to store the selected file path
        self.selected_file = None

        # Initialize filter states
        self.filter_state_alpha = 0
        self.filter_state_score = 0

    def create_main_view(self):
        # Create a QWidget for the main submission view
        main_widget = QWidget()

        # Create a label for instructions (top-left corner)
        self.label = QLabel("Please submit a file (PDF, TXT, CSV, JSON):")
        self.label.setFont(self.font)  # Apply font to the label
        self.label.setStyleSheet("color: white;")
        self.label.setAlignment(Qt.AlignLeft | Qt.AlignTop)

        # Create a label to show the selected file name
        self.file_name_label = QLabel("")
        self.file_name_label.setFont(self.font)
        self.file_name_label.setStyleSheet("color: white;")
        self.file_name_label.setAlignment(Qt.AlignLeft)
        self.file_name_label.setWordWrap(True)  # Enable word wrap
        self.file_name_label.setFixedWidth(400)  # Set a fixed width to control wrapping

        # Create a label to show the score after submission
        self.score_label = QLabel("")
        self.score_label.setFont(self.font)
        self.score_label.setStyleSheet("color: white;")
        self.score_label.setAlignment(Qt.AlignLeft)

        # Create a layout for the main view
        layout = QVBoxLayout()
        layout.addWidget(self.label)
        layout.addWidget(self.file_name_label)  # Display file name here
        layout.addWidget(self.score_label)      # Display score here

        # Create a vertical layout for buttons
        button_layout = QHBoxLayout()  # Vertical layout for buttons
        v_button_layout = QVBoxLayout()

        # Create a button to select a file
        self.file_button = QPushButton("Select File")
        self.file_button.setFont(self.font)
        self.file_button.setFixedSize(200, 30)  # Set same size for all buttons
        self.file_button.clicked.connect(self.open_file_dialog)
        button_layout.addWidget(self.file_button)

        # Create a submit button for files
        self.submit_button = QPushButton("Submit File")
        self.submit_button.setFont(self.font)
        self.submit_button.setFixedSize(200, 30)  # Set same size for all buttons
        self.submit_button.clicked.connect(self.submit_file)
        button_layout.addWidget(self.submit_button)

        # Create a button to view previous submissions (switches view)
        self.view_previous_button = QPushButton("View Previous Submissions")
        self.view_previous_button.setFont(self.font)
        self.view_previous_button.setFixedSize(406, 40)  # Set same size for all buttons
        self.view_previous_button.clicked.connect(self.switch_to_previous_submissions_view)
        v_button_layout.addWidget(self.view_previous_button)

        # Add the button layout to the main layout
        layout.addLayout(button_layout)
        layout.addLayout(v_button_layout)

        # Create horizontal layout for bar graphs
        bar_graph_layout = QHBoxLayout()

        # Create the bar graphs
        self.create_bar_graphs(bar_graph_layout)

        # Add the bar graph layout to the main layout
        layout.addLayout(bar_graph_layout)

        # Align everything to the top-left
        layout.setAlignment(Qt.AlignTop | Qt.AlignLeft)

        # Set layout for the main widget
        main_widget.setLayout(layout)

        return main_widget

    def create_bar_graphs(self, layout):
        # Base scores bar graph (with wider width)
        base_scores = [0, 0, 0]  # For Base Score, Impact Score, Exploitability Score
        base_labels = ["Base", "Impact", "Exploitability"]
        self.add_bar_graph(layout, base_scores, base_labels, "Base Scores", figsize=(6, 4), facecolor='#2D2D2D')  # Match background color

        # Temporal score bar graph (wider)
        temporal_score = [0]  # For Temporal Score
        temporal_labels = ["Temporal"]
        self.add_bar_graph(layout, temporal_score, temporal_labels, "Temporal Scores", figsize=(4, 4), facecolor='#2D2D2D')  # Match background color

        # Environmental score bar graph (wider)
        environmental_scores = [0]  # For Environmental Score
        environmental_labels = ["Environmental"]
        self.add_bar_graph(layout, environmental_scores, environmental_labels, "Environmental Score", figsize=(4, 4), facecolor='#2D2D2D')  # Match background color

        # Add new Security Best Practices bar graph (make it bigger)
        security_best_practices_scores = [0, 0, 0]  # For Physical Security, Personnel, and Policies
        security_best_practices_labels = ["Physical Security", "Personnel", "Policies"]
        self.add_bar_graph(layout, security_best_practices_scores, security_best_practices_labels, "Security Best Practices", figsize=(6, 4), facecolor='#2D2D2D')  # Match background color

        # Overall CVSS score bar graph
        overall_score = [0]  # For Overall CVSS Score
        overall_labels = ["Overall CVSS Score"]
        self.add_bar_graph(layout, overall_score, overall_labels, "Overall CVSS Score", figsize=(4, 4), facecolor='#2D2D2D')  # Match background color

    def add_bar_graph(self, layout, scores, labels, title, figsize=(4, 4), facecolor='#2D2D2D'):
        """Add a bar graph to the layout."""
        fig, ax = plt.subplots(figsize=figsize, facecolor=facecolor)  # Allow customizable figure size and facecolor
        ax.set_facecolor('#2D2D2D')  # Set the axes background color to match the application
        ax.bar(labels, scores, color='blue')
        ax.set_ylim(0, 10)  # Set y-axis limit from 0.0 to 10.0
        ax.set_title(title, color='white')  # Set title color to white
        ax.set_xlabel('Metrics', fontstyle='italic', color='white')  # Italicize x-axis label and set color
        ax.set_ylabel('Scores', fontstyle='italic', color='white')    # Italicize y-axis label and set color
        ax.tick_params(axis='both', colors='white')  # Set tick colors to white

        # Create a canvas to embed the plot in the PyQt app
        from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
        canvas = FigureCanvas(fig)

        # Add the canvas to the layout
        layout.addWidget(canvas)

    def create_previous_submissions_view(self):
        # Create a QWidget for the previous submissions view
        previous_submissions_widget = QWidget()

        # Create a layout for the previous submissions view
        layout = QVBoxLayout()

        # Create buttons for filtering
        self.filter_button_alpha = QPushButton("Filter Alphabetically")
        self.filter_button_alpha.setFont(self.font)
        self.filter_button_alpha.clicked.connect(self.toggle_filter_alpha)

        self.filter_button_score = QPushButton("Filter by Score")
        self.filter_button_score.setFont(self.font)
        self.filter_button_score.clicked.connect(self.toggle_filter_score)

        # Create a scroll area for the list of submissions
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)

        # Create a list widget to display submissions and scores
        self.list_widget = QListWidget(self)
        self.list_widget.setStyleSheet("color: white; background-color: #2E2E2E;")
        self.list_widget.setFont(self.font)

        # Add submissions to the list widget (only showing file names)
        self.update_previous_submissions_view()

        # Add the list widget to the scroll area
        scroll_area.setWidget(self.list_widget)

        # Create a download button
        self.download_button = QPushButton("Download Selected File")
        self.download_button.setFont(self.font)
        self.download_button.clicked.connect(self.download_file)

        # Create a delete button to remove selected submissions
        self.delete_button = QPushButton("Delete Selected Submission")
        self.delete_button.setFont(self.font)
        self.delete_button.clicked.connect(self.delete_file)

        # Create a button to go back to the main view
        self.back_button = QPushButton("Back to Main Menu")
        self.back_button.setFont(self.font)
        self.back_button.clicked.connect(self.switch_to_main_view)

        # Add the filter buttons, scroll area, and other buttons to the layout
        layout.addWidget(self.filter_button_alpha)  # Alphabetical filter button
        layout.addWidget(self.filter_button_score)   # Score filter button
        layout.addWidget(scroll_area)  # Add scroll area
        layout.addWidget(self.download_button)
        layout.addWidget(self.delete_button)
        layout.addWidget(self.back_button)

        # Set the layout for the previous submissions widget
        previous_submissions_widget.setLayout(layout)

        return previous_submissions_widget

    def open_file_dialog(self):
        # Open a file dialog to select a file
        file_dialog = QFileDialog(self)
        file_dialog.setNameFilter("Files (*.pdf *.txt *.csv *.json)")  # Allow PDF, TXT, and CSV files
        if file_dialog.exec():
            self.selected_file = file_dialog.selectedFiles()[0]
            self.file_name_label.setText(f"Selected: {os.path.basename(self.selected_file)}")  # Show file name

    def submit_file(self):
        # Handle file submission
        if self.selected_file:
            file_name = os.path.basename(self.selected_file)  # Get only the file name
            score = avg.main()  # Calculate score
            print(score)

            # Define the destination path in the submissions folder
            dest_path = os.path.join(self.submissions_folder, file_name)
            
            # Copy the file to the submissions folder
            shutil.copy(self.selected_file, dest_path)

            # Store the file and score in the submitted files list
            self.submitted_files.append((file_name, f"Score: {score}"))

            # Update the UI with submission status
            self.score_label.setText(f"File submitted successfully! Score: {score}")

            # Update the previous submissions view
            self.create_previous_submissions_view()

            # Save submissions to CSV and hash the submissions
            self.save_submissions()
            self.hash_submissions()
        else:
            self.file_name_label.setText("No file selected. Please select a file to submit.")

    def update_previous_submissions_view(self):
        # Clear and update the list widget in the previous submissions view
        self.list_widget.clear()
        for file, score in self.submitted_files:
            self.list_widget.addItem(f"{file} - {score}")  # Removed "PDF:" prefix

    def toggle_filter_alpha(self):
        # Toggle the alphabetical filtering state
        if self.filter_state_alpha == 0:
            # Apply alphabetical filter (ascending)
            self.submitted_files = sorted(self.submitted_files, key=lambda x: x[0])
            self.filter_state_alpha = 1
        elif self.filter_state_alpha == 1:
            # Apply alphabetical filter (descending)
            self.submitted_files = sorted(self.submitted_files, key=lambda x: x[0], reverse=True)
            self.filter_state_alpha = 2
        else:
            # Reset alphabetical filter
            self.submitted_files = self.load_submissions()
            self.filter_state_alpha = 0
        self.update_previous_submissions_view()

    def toggle_filter_score(self):
        # Toggle the score filtering state
        if self.filter_state_score == 0:
            # Apply score filter (ascending)
            self.submitted_files = sorted(self.submitted_files, key=lambda x: float(x[1].split()[1]))
            self.filter_state_score = 1
        elif self.filter_state_score == 1:
            # Apply score filter (descending)
            self.submitted_files = sorted(self.submitted_files, key=lambda x: float(x[1].split()[1]), reverse=True)
            self.filter_state_score = 2
        else:
            # Reset score filter
            self.submitted_files = self.load_submissions()
            self.filter_state_score = 0
        self.update_previous_submissions_view()

    def delete_file(self):
        # Delete the selected file from the list and submissions folder
        selected_items = self.list_widget.selectedItems()
        if selected_items:
            selected_item = selected_items[0].text()
            file_name, score = selected_item.split(" - ")  # Extract file name and score
            
            # Find the exact index of the selected submission in the submitted_files list
            for index, (f, s) in enumerate(self.submitted_files):
                if f == file_name and s == score:
                    # Remove the selected submission
                    del self.submitted_files[index]
                    break  # Stop after deleting the selected submission
            
            # Update the list view and save changes
            self.update_previous_submissions_view()
            self.save_submissions()
            print(f"Submission {file_name} with {score} has been deleted.")

    def download_file(self):
        # Download the selected file
        selected_items = self.list_widget.selectedItems()
        if selected_items:
            selected_item = selected_items[0].text()
            file_name = selected_item.split(" - ")[0]  # Extract the file name

            # Define the source path in the submissions folder
            source_path = os.path.join(self.submissions_folder, file_name)

            # Define the destination path for the download (e.g., current working directory or a 'downloads' folder)
            download_path = os.path.join(os.getcwd(), "downloads", file_name)
            os.makedirs(os.path.dirname(download_path), exist_ok=True)  # Ensure the 'downloads' folder exists

            # Copy the file to the downloads folder
            shutil.copy(source_path, download_path)

            print(f"{file_name} has been downloaded to {download_path}.")  # Output for debugging
    
    def save_submissions(self):
        # Save the submitted files and scores to a CSV file
        with open("submissions.csv", "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            for file, score in self.submitted_files:
                writer.writerow([file, score])

    def populate_file_list(self):
        # Clear the current file list
        self.file_list_widget.clear()

        # Add the submitted files to the file list widget
        for file_name in self.submitted_files:
            self.file_list_widget.addItem(file_name)

    def load_submissions(self):
        # Load submissions from a CSV file
        submissions = []
        try:
            with open("submissions.csv", "r") as csvfile:
                reader = csv.reader(csvfile)
                for row in reader:
                    submissions.append((row[0], row[1]))  # (File name, Score)
        except FileNotFoundError:
            print("No previous submissions found.")
        return submissions
    
    def hash_submissions(self):
        # Hash the submissions CSV file
        with open("submissions.csv", "rb") as file:
            file_data = file.read()
            file_hash = hashlib.sha256(file_data).hexdigest()
            print(f"CSV File Hash: {file_hash}")

    def switch_to_main_view(self):
        # Switch to the main submission view
        self.stacked_widget.setCurrentWidget(self.previous_submissions_view)

    def switch_to_previous_submissions_view(self):
        # Switch to the previous submissions view
        self.stacked_widget.setCurrentWidget(self.previous_submissions_view)

    def calculate_cvss_score(self):
        # Execute the main method in average.py which handles input in the terminal
        try:
            score = avg.main()  # Make sure avg.main() returns the calculated score
        except Exception as e:
            print(f"An error occurred during CVSS score calculation: {e}")
            score = 0.0

        return round(score, 2)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SystemEvaluationApp()
    window.show()
    sys.exit(app.exec())

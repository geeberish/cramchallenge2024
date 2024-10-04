from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QVBoxLayout, QFileDialog, QHBoxLayout, QListWidget, QStackedWidget, QScrollArea
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QPalette, QColor, QFont
import shutil
import sys
import os
import csv
import random  # For generating random scores
import hashlib  # For hashing the CSV file
from average import *
import average as avg
sys.path.insert(1, 'C:/Users/Acer/Cram/cramchallenge2024/gui')
class SystemEvaluationApp(QWidget):
    def __init__(self):
        super().__init__()

        # Initialize the submitted_files list before calling any methods that use it
        self.submitted_files = self.load_submissions()  # Load previously submitted files

        # Set window title and size
        self.setWindowTitle("System Evaluation App")
        self.setFixedSize(700, 500)  # Canvas height reduced to 500px

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

        # Create the previous submissions view
        self.previous_submissions_view = self.create_previous_submissions_view()

        # Add the views to the stacked widget
        self.stacked_widget.addWidget(self.main_view)
        self.stacked_widget.addWidget(self.previous_submissions_view)

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
        self.label = QLabel("Please submit a file (PDF, TXT, CSV):")
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

        # Align everything to the top-left
        layout.setAlignment(Qt.AlignTop | Qt.AlignLeft)

        # Set layout for the main widget
        main_widget.setLayout(layout)

        return main_widget

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
        file_dialog.setNameFilter("Files (*.pdf *.txt *.csv)")  # Allow PDF, TXT, and CSV files
        if file_dialog.exec():
            self.selected_file = file_dialog.selectedFiles()[0]
            self.file_name_label.setText(f"Selected: {os.path.basename(self.selected_file)}")  # Show file name

    def submit_file(self):
        # Handle file submission
        if self.selected_file:
            file_name = os.path.basename(self.selected_file)  # Get only the file name
            #score = random.randint(60, 100)  # Simulate a random score between 60 and 100
            score = avg.main()
            self.submitted_files.append((file_name, f"Score: {score}"))  # Append file name and score
            self.score_label.setText(f"File submitted successfully! Score: {score}")
            # Update the submissions view with the new file
            self.update_previous_submissions_view()
            self.save_submissions()  # Save submissions to CSV file
            self.hash_submissions()   # Hash the CSV file
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
            # Sort A-Z (all names in lowercase)
            self.submitted_files.sort(key=lambda x: x[0].lower())
            self.filter_state_alpha = 1
        elif self.filter_state_alpha == 1:
            # Sort Z-A (all names in lowercase)
            self.submitted_files.sort(key=lambda x: x[0].lower(), reverse=True)
            self.filter_state_alpha = 2
        else:
            # Reset to original order
            self.submitted_files = self.load_submissions()  # Reload original order
            self.filter_state_alpha = 0
        self.update_previous_submissions_view()

    def toggle_filter_score(self):
        # Toggle the score filtering state
        if self.filter_state_score == 0:
            # Sort by score descending (assuming score is the second element in the tuple)
            self.submitted_files.sort(key=lambda x: int(x[1].split(": ")[1]), reverse=True)
            self.filter_state_score = 1
        elif self.filter_state_score == 1:
            # Sort by score ascending
            self.submitted_files.sort(key=lambda x: int(x[1].split(": ")[1]))
            self.filter_state_score = 2
        else:
            # Reset to original order
            self.submitted_files = self.load_submissions()  # Reload original order
            self.filter_state_score = 0
        self.update_previous_submissions_view()

    def download_file(self):
        # Download the selected file
        selected_items = self.list_widget.selectedItems()
        if selected_items:
            selected_item = selected_items[0].text()
            file_name = selected_item.split(" - ")[0]  # Extract the file name
            shutil.copy(file_name, os.path.join(os.getcwd(), "downloads", file_name))  # Copy to downloads folder
            print(f"{file_name} has been downloaded.")  # Output for debugging

    def delete_file(self):
        # Delete the selected file from the submissions
        selected_items = self.list_widget.selectedItems()
        if selected_items:
            selected_item = selected_items[0].text()
            file_name = selected_item.split(" - ")[0]  # Extract the file name
            self.submitted_files = [file for file in self.submitted_files if file[0] != file_name]  # Remove the submission
            self.update_previous_submissions_view()  # Update the display
            self.save_submissions()  # Save updated submissions to CSV
            print(f"{file_name} has been deleted.")  # Output for debugging

    def switch_to_previous_submissions_view(self):
        self.stacked_widget.setCurrentIndex(1)  # Switch to previous submissions view

    def switch_to_main_view(self):
        self.stacked_widget.setCurrentIndex(0)  # Switch back to main view

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

    def save_submissions(self):
        # Save the submitted files to a CSV file
        with open("submissions.csv", "w", newline='') as csvfile:
            writer = csv.writer(csvfile)
            for file, score in self.submitted_files:
                writer.writerow([file, score])

    def hash_submissions(self):
        # Hash the CSV file
        with open("submissions.csv", "rb") as f:
            data = f.read()
            hash_value = hashlib.md5(data).hexdigest()  # MD5 hash of the file
            print(f"Hash of submissions.csv: {hash_value}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SystemEvaluationApp()
    window.show()
    sys.exit(app.exec())

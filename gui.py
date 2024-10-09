from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QVBoxLayout, QFileDialog, QHBoxLayout, QListWidget, QMessageBox, QStackedWidget, QScrollArea
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
import subprocess

from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas

class SystemEvaluationApp(QWidget):
    def __init__(self):
        super().__init__()

        # Create the submissions folder if it doesn't exist
        self.submissions_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'submissions')
        if not os.path.exists(self.submissions_folder):
            os.makedirs(self.submissions_folder)

        # Initialize the submitted_files list before calling any methods that use it
        self.submitted_files = self.load_submissions()
        app_icon = QIcon('files/logo.png')

        # Set window title and size
        self.setWindowIcon(app_icon)
        self.setWindowTitle("ACRES")
        self.showMaximized()

        # Set background color and font
        palette = self.palette()
        palette.setColor(QPalette.Window, QColor(45, 45, 45))
        palette.setColor(QPalette.WindowText, QColor(255, 255, 255))
        self.setPalette(palette)

        self.font = QFont("Helvetica", 12)
        self.setFont(self.font)

        # Set up a stacked widget to switch between the main and previous submissions view
        self.stacked_widget = QStackedWidget(self)
        self.main_view = self.create_main_view()
        self.stacked_widget.addWidget(self.main_view)

        self.previous_submissions_view = self.create_previous_submissions_view()
        self.stacked_widget.addWidget(self.previous_submissions_view)

        self.select_file_view = self.create_file_select_view()
        self.stacked_widget.addWidget(self.select_file_view)

        layout = QVBoxLayout(self)
        layout.addWidget(self.stacked_widget)

        self.selected_file = None

        self.filter_state_alpha = 0
        self.filter_state_score = 0
        self.resize(1024, 768)  # Set to your desired default size

    def create_main_view(self):
        main_widget = QWidget()
        self.label = QLabel("Please submit a file (PDF, TXT, CSV, JSON):")
        self.label.setFont(self.font)
        self.label.setStyleSheet("color: white;")
        self.label.setAlignment(Qt.AlignLeft | Qt.AlignTop)

        self.file_name_label = QLabel("")
        self.file_name_label.setFont(self.font)
        self.file_name_label.setStyleSheet("color: white;")
        self.file_name_label.setAlignment(Qt.AlignLeft)
        self.file_name_label.setWordWrap(True)
        self.file_name_label.setFixedWidth(400)

        self.score_label = QLabel("")
        self.score_label.setFont(self.font)
        self.score_label.setStyleSheet("color: white;")
        self.score_label.setAlignment(Qt.AlignLeft)

        layout = QVBoxLayout()
        layout.addWidget(self.label)
        layout.addWidget(self.file_name_label)
        layout.addWidget(self.score_label)

        button_layout = QHBoxLayout()

        self.file_button = QPushButton("Select Files")
        self.file_button.setFont(self.font)
        # self.file_button.setFixedSize(200, 30)
        self.file_button.setFixedSize(406, 40)
        self.file_button.clicked.connect(self.switch_to_file_select_view)
        button_layout.addWidget(self.file_button)

        # self.submit_button = QPushButton("Submit File")
        # self.submit_button.setFont(self.font)
        # self.submit_button.setFixedSize(200, 30)
        # self.submit_button.clicked.connect(self.submit_file)
        # button_layout.addWidget(self.submit_button)

        button_layout.setAlignment(Qt.AlignLeft)
        v_button_layout = QVBoxLayout()
        self.view_previous_button = QPushButton("View Previous Submissions")
        self.view_previous_button.setFont(self.font)
        self.view_previous_button.setFixedSize(406, 40)
        self.view_previous_button.clicked.connect(self.switch_to_previous_submissions_view)
        v_button_layout.addWidget(self.view_previous_button)

        layout.addLayout(button_layout)
        layout.addLayout(v_button_layout)

        bar_graph_layout = QHBoxLayout()

        self.figures = {}
        self.create_bar_graphs(bar_graph_layout)
        layout.addLayout(bar_graph_layout)

        layout.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        main_widget.setLayout(layout)

        return main_widget

    def create_bar_graphs(self, layout):
        self.figures = {}
        self.figures['base'] = self.add_bar_graph(layout, [0, 0, 0], ["Base", "Impact", "Exploitability"], "Base Scores", (6, 4))
        self.figures['temporal'] = self.add_bar_graph(layout, [0], ["Temporal"], "Temporal Scores", (4, 4))
        self.figures['environmental'] = self.add_bar_graph(layout, [0], ["Environmental"], "Environmental Score", (4, 4))
        self.figures['security'] = self.add_bar_graph(layout, [0, 0, 0], ["Physical Security", "Personnel", "Policies"], "Security Best Practices Scores", (6, 4), y_limit=(0, 1))  # Set y limit to 0-1
        self.figures['overall'] = self.add_bar_graph(layout, [0], ["Overall CVSS Score"], "Overall CVSS Score", (4, 4))

    
    def add_bar_graph(self, layout, scores, labels, title, figsize, y_limit=(0, 10)):
        fig, ax = plt.subplots(figsize=figsize, facecolor='#2D2D2D')
        ax.set_facecolor('#2D2D2D')
        ax.bar(labels, scores, color='blue', edgecolor='white')
        ax.set_ylim(y_limit)  # Set dynamic y limits based on the argument
        ax.set_title(title, color='white')
        ax.set_xlabel('Metrics', fontstyle='italic', color='white')
        ax.set_ylabel('Scores', fontstyle='italic', color='white')
        ax.tick_params(axis='both', colors='white')

        ax.spines['top'].set_color('white')
        ax.spines['bottom'].set_color('white')
        ax.spines['left'].set_color('white')
        ax.spines['right'].set_color('white')

        canvas = FigureCanvas(fig)
        layout.addWidget(canvas)

        return {'canvas': canvas, 'ax': ax, 'fig': fig, 'labels': labels}


    def create_previous_submissions_view(self):
        # Create a QWidget for the previous submissions view
        previous_submissions_widget = QWidget()

        # Create a layout for the previous submissions view
        layout = QVBoxLayout()

        # Create buttons for filtering
        self.filter_button_alpha = QPushButton("Filter Alphabetically")
        self.filter_button_alpha.setFont(self.font)
        self.filter_button_alpha.setFixedSize(203, 30)  # Half the original size
        self.filter_button_alpha.clicked.connect(self.toggle_filter_alpha)

        self.filter_button_score = QPushButton("Filter by Score")
        self.filter_button_score.setFont(self.font)
        self.filter_button_score.setFixedSize(203, 30)  # Half the original size
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
        self.download_button.setFixedSize(203, 30)  # Half the original size
        self.download_button.clicked.connect(self.download_file)

        # Create a delete button to remove selected submissions
        self.delete_button = QPushButton("Delete Selected Submission")
        self.delete_button.setFont(self.font)
        self.delete_button.setFixedSize(203, 30)  # Half the original size
        self.delete_button.clicked.connect(self.delete_file)

        # Create a button to go back to the main view
        self.back_button = QPushButton("Back to Main Menu")
        self.back_button.setFont(self.font)
        self.back_button.setFixedSize(203, 30)  # Half the original size
        self.back_button.clicked.connect(self.switch_to_main_view)

        # Create a horizontal layout for the buttons to center them
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.download_button)
        button_layout.addWidget(self.delete_button)
        button_layout.addWidget(self.back_button)

        # Center the buttons in the layout
        button_layout.setAlignment(Qt.AlignCenter)

        # Add the filter buttons, scroll area, and button layout to the main layout
        layout.addWidget(self.filter_button_alpha)  # Alphabetical filter button
        layout.addWidget(self.filter_button_score)   # Score filter button
        layout.addWidget(scroll_area)  # Add scroll area
        layout.addLayout(button_layout)  # Add the centered button layout

        layout.setAlignment(Qt.AlignCenter)

        # Set the layout for the previous submissions widget
        previous_submissions_widget.setLayout(layout)

        return previous_submissions_widget
    
    def create_file_select_view(self):
        # Create a QWidget for the previous submissions view
        file_select_widget = QWidget()

        # Create a layout for the previous submissions view
        layout = QVBoxLayout()

        self.cf_file_name_label = QLabel("")
        self.cf_file_name_label.setFont(self.font)
        self.cf_file_name_label.setStyleSheet("color: white;")
        self.cf_file_name_label.setAlignment(Qt.AlignLeft)
        self.cf_file_name_label.setWordWrap(True)
        self.cf_file_name_label.setFixedWidth(400)

        self.dv_file_name_label = QLabel("")
        self.dv_file_name_label.setFont(self.font)
        self.dv_file_name_label.setStyleSheet("color: white;")
        self.dv_file_name_label.setAlignment(Qt.AlignLeft)
        self.dv_file_name_label.setWordWrap(True)
        self.dv_file_name_label.setFixedWidth(400)

        self.h_file_name_label = QLabel("")
        self.h_file_name_label.setFont(self.font)
        self.h_file_name_label.setStyleSheet("color: white;")
        self.h_file_name_label.setAlignment(Qt.AlignLeft)
        self.h_file_name_label.setWordWrap(True)
        self.h_file_name_label.setFixedWidth(400)

        self.s_file_name_label = QLabel("")
        self.s_file_name_label.setFont(self.font)
        self.s_file_name_label.setStyleSheet("color: white;")
        self.s_file_name_label.setAlignment(Qt.AlignLeft)
        self.s_file_name_label.setWordWrap(True)
        self.s_file_name_label.setFixedWidth(400)

        self.sum_file_name_label = QLabel("")
        self.sum_file_name_label.setFont(self.font)
        self.sum_file_name_label.setStyleSheet("color: white;")
        self.sum_file_name_label.setAlignment(Qt.AlignLeft)
        self.sum_file_name_label.setWordWrap(True)
        self.sum_file_name_label.setFixedWidth(400)

        # Create a button to go back to the main view
        self.back_button = QPushButton("Back to Main Menu")
        self.back_button.setFont(self.font)
        self.back_button.setFixedSize(203, 30)  # Half the original size
        self.back_button.clicked.connect(self.switch_to_main_view)


        self.label2 = QLabel("Please submit a file for Critical Functions (CSV, JSON):")
        self.label2.setFont(self.font)
        self.label2.setStyleSheet("color: white;")
        self.label2.setAlignment(Qt.AlignLeft | Qt.AlignTop)

        self.select_cf_button = QPushButton("Select File")
        self.select_cf_button.setFont(self.font)
        self.select_cf_button.setFixedSize(203, 30)  # Half the original size
        self.select_cf_button.clicked.connect(lambda: self.open_file_dialog("cf"))

        self.label3 = QLabel("Please submit a file for Detected Vulnerabilities (CSV, JSON):")
        self.label3.setFont(self.font)
        self.label3.setStyleSheet("color: white;")
        self.label3.setAlignment(Qt.AlignLeft | Qt.AlignTop)

        self.select_dv_button = QPushButton("Select File")
        self.select_dv_button.setFont(self.font)
        self.select_dv_button.setFixedSize(203, 30)  # Half the original size
        self.select_dv_button.clicked.connect(lambda: self.open_file_dialog("dv"))

        self.label4 = QLabel("Please submit a file for Hardware (CSV, JSON):")
        self.label4.setFont(self.font)
        self.label4.setStyleSheet("color: white;")
        self.label4.setAlignment(Qt.AlignLeft | Qt.AlignTop)

        self.select_h_button = QPushButton("Select File")
        self.select_h_button.setFont(self.font)
        self.select_h_button.setFixedSize(203, 30)  # Half the original size
        self.select_h_button.clicked.connect(lambda: self.open_file_dialog("h"))

        self.label5 = QLabel("Please submit a file for Software (CSV, JSON):")
        self.label5.setFont(self.font)
        self.label5.setStyleSheet("color: white;")
        self.label5.setAlignment(Qt.AlignLeft | Qt.AlignTop)

        self.select_s_button = QPushButton("Select File")
        self.select_s_button.setFont(self.font)
        self.select_s_button.setFixedSize(203, 30)  # Half the original size
        self.select_s_button.clicked.connect(lambda: self.open_file_dialog("s"))

        self.label6 = QLabel("Please submit a file for Summaries (TXT):")
        self.label6.setFont(self.font)
        self.label6.setStyleSheet("color: white;")
        self.label6.setAlignment(Qt.AlignLeft | Qt.AlignTop)

        self.select_sum_button = QPushButton("Select File")
        self.select_sum_button.setFont(self.font)
        self.select_sum_button.setFixedSize(203, 30)  # Half the original size
        self.select_sum_button.clicked.connect(lambda: self.open_file_dialog("sum"))

        self.submit_button = QPushButton("Submit File")
        self.submit_button.setFont(self.font)
        self.submit_button.setFixedSize(200, 30)
        self.submit_button.clicked.connect(self.submit_file)

        # Add labels and buttons to the layout
        
        layout.addWidget(self.label2)
        layout.addWidget(self.cf_file_name_label)
        layout.addWidget(self.select_cf_button)
        layout.addStretch()  # Optional: Add stretchable space to separate sections

        layout.addWidget(self.label3)
        layout.addWidget(self.dv_file_name_label)
        layout.addWidget(self.select_dv_button)
        layout.addStretch()  # Optional: Add stretchable space to separate sections

        layout.addWidget(self.label4)
        layout.addWidget(self.h_file_name_label)
        layout.addWidget(self.select_h_button)
        layout.addStretch()  # Optional: Add stretchable space to separate sections

        layout.addWidget(self.label5)
        layout.addWidget(self.s_file_name_label)
        layout.addWidget(self.select_s_button)
        layout.addStretch()  # Optional: Add stretchable space to separate sections

        layout.addWidget(self.label6)
        layout.addWidget(self.sum_file_name_label)
        layout.addWidget(self.select_sum_button)
        layout.addStretch()  # Optional: Add stretchable space to separate sections

        # Add the submit button without additional spacing
        layout.addWidget(self.submit_button)
        layout.addWidget(self.back_button)

        # Set the layout for the previous submissions widget
        file_select_widget.setLayout(layout)

        return file_select_widget
    
    def update_bar_graph(self, name, scores):
        print(f"Updating {name} graph with scores: {scores}")  # Debugging print
        fig_data = self.figures[name]
        ax = fig_data['ax']
        ax.clear()
        
        ax.set_facecolor('#2D2D2D')
        ax.bar(fig_data['labels'], scores, color='blue', edgecolor='white')
        
        # Set the y-limits based on the graph name
        if name == 'security':
            ax.set_ylim(0, 1)  # For security scores, keep y limits from 0.0 to 1.0
        else:
            ax.set_ylim(0, 10)  # For other graphs, set y limits from 0 to 10

        fig_data['canvas'].draw()
        fig_data['canvas'].flush_events()


    def open_file_dialog(self, file_type):
        # Open a file dialog to select a file based on the type
        file_dialog = QFileDialog(self)
        file_dialog.setNameFilter("Files (*.pdf *.txt *.csv *.json)")  # Allow PDF, TXT, and CSV files
        if file_dialog.exec():
            selected_file = file_dialog.selectedFiles()[0]
            file_name = os.path.basename(selected_file)

            # Set the selected file based on the provided type
            if file_type == "cf":
                self.selected_cf_button = selected_file
                self.cf_file_name_label.setText(f"Selected: {file_name}")
            elif file_type == "dv":
                self.selected_dv_button = selected_file
                self.dv_file_name_label.setText(f"Selected: {file_name}")
            elif file_type == "h":
                self.selected_h_button = selected_file
                self.h_file_name_label.setText(f"Selected: {file_name}")
            elif file_type == "s":
                self.selected_s_button = selected_file
                self.s_file_name_label.setText(f"Selected: {file_name}")
            elif file_type == "sum":
                self.selected_sum_button = selected_file
                self.sum_file_name_label.setText(f"Selected: {file_name}")


    def submit_file(self):
        # Check for required files except for Detected Vulnerabilities
        if not self.select_cf_button or not self.selected_h_button or not self.selected_s_button or not self.selected_sum_button:
            missing_files = []
            if not self.selected_cf_button:
                missing_files.append("Critical Functions")
            if not self.selected_h_button:
                missing_files.append("Hardware")
            if not self.selected_s_button:
                missing_files.append("Software")
            if not self.selected_sum_button:
                missing_files.append("Summaries")
            
            QMessageBox.warning(self, "Missing Files", "Please select the following required files:\n" + "\n".join(missing_files))
            return  # Exit the function if there are missing files

        # Process the submitted files here (e.g., copy files to the submissions folder, etc.)
        files_to_submit = {
            "Critical Functions": self.selected_cf_button,
            "Detected Vulnerabilities": self.selected_dv_button,
            "Hardware": self.selected_h_button,
            "Software": self.selected_s_button,
            "Summaries": self.selected_sum_button,
        }

        # Copy files to the submissions folder and collect them for the CSV
        submitted_files = []
        for file_name, file_path in files_to_submit.items():
            if file_path:  # Only save if the file is selected
                shutil.copy(file_path, self.submissions_folder)
                submitted_files.append(file_name)  # Save the file name for later use in the CSV

        # Assuming avg.main() function returns the required scores
        base, impact_sub, exploitability_sub, temporal, environmental, physical_security, personnel_training, policies, average_cvss = avg.main()

        # Show success message
        self.score_label.setText(f"Files submitted successfully! Score: {average_cvss}")
        self.update_previous_submissions_view()
        
        # Save the submitted files and the scores to the submissions.csv file
        with open("submissions.csv", "a", newline="") as csvfile:  # 'a' mode to append
            writer = csv.writer(csvfile)
            for file in submitted_files:
                writer.writerow([file, f"Score: {average_cvss}"])  # Add file name and score to the CSV

        # Hash the submissions
        self.hash_submissions()

        # Update the bar graphs with new scores
        self.update_bar_graph('base', [base, impact_sub, exploitability_sub])
        self.update_bar_graph('temporal', [temporal])
        self.update_bar_graph('environmental', [environmental])
        self.update_bar_graph('security', [physical_security, personnel_training, policies])
        self.update_bar_graph('overall', [average_cvss])

        # Reset selections after submission
        self.reset_file_selections()


    def reset_file_selections(self):
        # Clear the selections for all file types
        self.selected_cf_file = None
        self.selected_dv_file = None
        self.selected_h_file = None
        self.selected_s_file = None
        self.selected_sum_file = None
        
        # Clear the labels in the UI
        self.cf_file_name_label.setText("")
        self.dv_file_name_label.setText("")
        self.h_file_name_label.setText("")
        self.s_file_name_label.setText("")
        self.sum_file_name_label.setText("")

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

            # Define the destination path for the download (user's Downloads folder)
            download_path = os.path.join(os.path.expanduser("~"), "Downloads", file_name)

            # Copy the file to the Downloads folder
            shutil.copy(source_path, download_path)

            # Open the Downloads folder
            subprocess.Popen(f'explorer "{os.path.expanduser("~\\Downloads")}"')

            print(f"{file_name} has been downloaded to {download_path}.")  # Output for debugging
        else:
            print("No file selected for download.")
    
    def save_submissions(self):
        # Save the submitted files and scores to a CSV file
        with open("submissions.csv", "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            
            # Write header for the CSV file
            writer.writerow(["File Name", "Score"])
            
            # Write the submitted files and scores
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
        self.stacked_widget.setCurrentIndex(0)

    def switch_to_previous_submissions_view(self):
        # Switch to the previous submissions view
        self.stacked_widget.setCurrentWidget(self.previous_submissions_view)

    def switch_to_file_select_view(self):
        # Switch to the previous submissions viewprevious_submissions_view
        self.stacked_widget.setCurrentWidget(self.select_file_view)

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
    window.show()  # Show the window first
    window.showMaximized()  # Then maximize it
    sys.exit(app.exec())

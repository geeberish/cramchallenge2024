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
import subprocess
from invoke_model import load_and_invoke_model  # Import the function to invoke the SageMaker model


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

        self.file_button = QPushButton("Select File")
        self.file_button.setFont(self.font)
        self.file_button.setFixedSize(200, 30)
        self.file_button.clicked.connect(self.open_file_dialog)
        button_layout.addWidget(self.file_button)

        self.submit_button = QPushButton("Submit File")
        self.submit_button.setFont(self.font)
        self.submit_button.setFixedSize(200, 30)
        self.submit_button.clicked.connect(self.submit_file)
        button_layout.addWidget(self.submit_button)

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


    def open_file_dialog(self):
        # Open a file dialog to select a file
        file_dialog = QFileDialog(self)
        file_dialog.setNameFilter("Files (*.pdf *.txt *.csv *.json)")  # Allow PDF, TXT, and CSV files
        if file_dialog.exec():
            self.selected_file = file_dialog.selectedFiles()[0]
            self.file_name_label.setText(f"Selected: {os.path.basename(self.selected_file)}")  # Show file name

    def submit_file(self):
        if self.selected_file:
            file_name = os.path.basename(self.selected_file)
            
            # Copy the submitted file to the submission folder
            dest_path = os.path.join(self.submissions_folder, file_name)
            shutil.copy(self.selected_file, dest_path)

            # Load and invoke the SageMaker model
            endpoint_name = 'WhiteRabbitNeo'  # Your SageMaker endpoint name
            model_output = load_and_invoke_model(self.selected_file, endpoint_name)

            # Extract scores from the model output
            base = model_output.get("base", 0)
            impact_sub = model_output.get("impact_sub", 0)
            exploitability_sub = model_output.get("exploitability_sub", 0)
            temporal = model_output.get("temporal", 0)
            environmental = model_output.get("environmental", 0)
            physical_security = model_output.get("physical_security", 0)
            personnel_training = model_output.get("personnel_training", 0)
            policies = model_output.get("policies", 0)
            average_cvss = model_output.get("average_cvss", 0)

            # Update UI with the model output
            self.submitted_files.append((file_name, f"Score: {average_cvss}"))
            self.score_label.setText(f"File submitted successfully! Score: {average_cvss}")
            self.update_previous_submissions_view()
            self.save_submissions()
            self.hash_submissions()

            # Update the bar graphs with new scores
            self.update_bar_graph('base', [base, impact_sub, exploitability_sub])
            self.update_bar_graph('temporal', [temporal])
            self.update_bar_graph('environmental', [environmental])
            self.update_bar_graph('security', [physical_security, personnel_training, policies])
            self.update_bar_graph('overall', [average_cvss])
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
        # Get the selected item from the list widget
        selected_items = self.list_widget.selectedItems()
        if selected_items:
            selected_item = selected_items[0].text()
            file_name = selected_item.split(" - ")[0]  # Extract the file name

            # Define the source path in the submissions folder
            source_path = os.path.join(self.submissions_folder, file_name)

            # Get the path to the Downloads folder
            downloads_folder = os.path.join(os.path.expanduser("~"), "Downloads")

            # Open the OS's native "Save As" dialog using QFileDialog.getSaveFileName
            save_file_dialog = QFileDialog.getSaveFileName(self, 
                                                        "Save File As", 
                                                        os.path.join(downloads_folder, file_name),  # Default to Downloads folder
                                                        "All Files (*)")

            # If the user chooses a file path
            if save_file_dialog[0]:
                destination_path = save_file_dialog[0]  # Get the selected file path

                # Copy the file to the destination path
                shutil.copy(source_path, destination_path)

                # Output success message
                print(f"{file_name} has been saved to {destination_path}.")
            else:
                print("Download canceled by the user.")
        else:
            print("No file selected for download.")
    
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
        self.stacked_widget.setCurrentIndex(0)

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
    window.show()  # Show the window first
    window.showMaximized()  # Then maximize it
    sys.exit(app.exec())

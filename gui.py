from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QVBoxLayout, QFileDialog, QHBoxLayout, QListWidget, QStackedWidget, QScrollArea
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QPalette, QColor, QFont, QIcon, Q 
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

        # Store references to the canvas widgets for bar graphs
        self.canvas_widgets = []

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

        # Create a horizontal layout for buttons
        button_layout = QHBoxLayout()

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

        # Align the buttons to the left
        button_layout.setAlignment(Qt.AlignLeft)

        # Create a vertical layout for the "View Previous Submissions" button
        v_button_layout = QVBoxLayout()
        self.view_previous_button = QPushButton("View Previous Submissions")
        self.view_previous_button.setFont(self.font)
        self.view_previous_button.setFixedSize(406, 40)  # Set same size for all buttons
        self.view_previous_button.clicked.connect(self.switch_to_previous_submissions_view)
        v_button_layout.addWidget(self.view_previous_button)

        # Add the button layouts to the main layout
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
        canvas = self.add_bar_graph(layout, base_scores, base_labels, "Base Scores", figsize=(6, 4), facecolor='#2D2D2D')  # Match background color
        self.canvas_widgets.append(canvas)

        # Temporal score bar graph (wider)
        temporal_score = [0]  # For Temporal Score
        temporal_labels = ["Temporal"]
        canvas = self.add_bar_graph(layout, temporal_score, temporal_labels, "Temporal Scores", figsize=(4, 4), facecolor='#2D2D2D')  # Match background color
        self.canvas_widgets.append(canvas)

        # Environmental score bar graph (wider)
        environmental_scores = [0]  # For Environmental Score
        environmental_labels = ["Environmental"]
        canvas = self.add_bar_graph(layout, environmental_scores, environmental_labels, "Environmental Score", figsize=(4, 4), facecolor='#2D2D2D')  # Match background color
        self.canvas_widgets.append(canvas)

        # Add new Security Best Practices bar graph (make it bigger)
        security_best_practices_scores = [0, 0, 0]  # For Physical Security, Personnel, and Policies
        security_best_practices_labels = ["Physical Security", "Personnel", "Policies"]
        canvas = self.add_bar_graph(layout, security_best_practices_scores, security_best_practices_labels, "Security Best Practices", figsize=(6, 4), facecolor='#2D2D2D')  # Match background color
        self.canvas_widgets.append(canvas)

        # Overall CVSS score bar graph
        overall_score = [0]  # For Overall CVSS Score
        overall_labels = ["Overall CVSS Score"]
        canvas = self.add_bar_graph(layout, overall_score, overall_labels, "Overall CVSS Score", figsize=(4, 4), facecolor='#2D2D2D')  # Match background color
        self.canvas_widgets.append(canvas)

    def add_bar_graph(self, layout, scores, labels, title, figsize=(4, 4), facecolor='#2D2D2D'):
        """Add a bar graph to the layout."""
        fig, ax = plt.subplots(figsize=figsize, facecolor=facecolor)  # Allow customizable figure size and facecolor
        ax.set_facecolor('#2D2D2D')  # Set the axes background color to match the application
        
        # Create bars with a white edge color
        ax.bar(labels, scores, color='blue', edgecolor='white')  # Add white border to the bars
        
        ax.set_ylim(0, 10)  # Set y-axis limit from 0.0 to 10.0
        ax.set_title(title, color='white')  # Set title color to white
        ax.set_xlabel('Metrics', fontstyle='italic', color='white')  # Italicize x-axis label and set color
        ax.set_ylabel('Score', fontstyle='italic', color='white')  # Italicize y-axis label and set color
        ax.tick_params(axis='x', colors='white')  # Set x-axis tick color to white
        ax.tick_params(axis='y', colors='white')  # Set y-axis tick color to white
        
        # Save the graph to a temporary image file
        graph_path = os.path.join(self.submissions_folder, "temp_graph.png")
        plt.savefig(graph_path, facecolor=facecolor)  # Save with the same background color
        plt.close(fig)  # Close the figure to avoid display

        # Add the graph image to the layout
        canvas = QLabel()  # Use QLabel to display the image
        pixmap = QPixmap(graph_path)
        canvas.setPixmap(pixmap)
        layout.addWidget(canvas)

        return canvas  # Return the canvas for future updates

    def open_file_dialog(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_name, _ = QFileDialog.getOpenFileName(self, "Select File", "", "All Files (*);;CSV Files (*.csv);;Text Files (*.txt);;PDF Files (*.pdf);;JSON Files (*.json)", options=options)
        if file_name:
            self.selected_file = file_name
            self.file_name_label.setText(os.path.basename(file_name))  # Update label with selected file name

    def load_submissions(self):
        # Load previously submitted files from the submissions folder
        if not os.path.exists(self.submissions_folder):
            return []
        return [f for f in os.listdir(self.submissions_folder) if f.endswith(('.csv', '.txt', '.pdf', '.json'))]

    def submit_file(self):
        if self.selected_file:
            # Copy the selected file to the submissions folder
            file_name = os.path.basename(self.selected_file)
            destination = os.path.join(self.submissions_folder, file_name)
            shutil.copy2(self.selected_file, destination)

            # Compute a hash of the submitted file to ensure uniqueness
            file_hash = self.compute_file_hash(destination)

            # Read scores from the submitted file
            scores = self.extract_scores(destination)  # Implement this method to read scores from the file
            self.update_bar_graphs(scores)  # Update bar graphs with new scores

            # Display the scores
            self.score_label.setText(f"Scores: {scores}")  # Display scores in the label

            # Reload the submitted files list
            self.submitted_files = self.load_submissions()

    def compute_file_hash(self, file_path):
        """Compute a SHA256 hash of the file."""
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()

    def extract_scores(self, file_path):
        """Extract scores from the submitted file. This is a placeholder function."""
        # Implement your score extraction logic here
        return [5, 7, 3, 6, 9]  # Example scores for demonstration

    def update_bar_graphs(self, scores):
        """Update the bar graphs with new scores."""
        if len(scores) >= len(self.canvas_widgets):
            # Update the first three graphs with base scores
            for i in range(3):
                canvas = self.canvas_widgets[i]
                self.update_graph(canvas, scores[i])

            # Update the fourth graph (Security Best Practices)
            for i in range(3, 6):
                canvas = self.canvas_widgets[3]  # Assuming index 3 is for Security Best Practices
                self.update_graph(canvas, scores[i])

            # Update the fifth graph (Overall CVSS Score)
            canvas = self.canvas_widgets[4]  # Assuming index 4 is for Overall CVSS Score
            self.update_graph(canvas, scores[6])

    def update_graph(self, canvas, score):
        """Update a specific graph's score."""
        # Update the image displayed in the canvas
        # You would regenerate the graph image based on the new score
        fig, ax = plt.subplots(figsize=(4, 4), facecolor='#2D2D2D')
        ax.set_facecolor('#2D2D2D')
        
        # Create bars with the updated score
        ax.bar(["Score"], [score], color='blue', edgecolor='white')

        ax.set_ylim(0, 10)
        ax.set_title("Updated Score", color='white')
        ax.set_xlabel('Metrics', fontstyle='italic', color='white')
        ax.set_ylabel('Score', fontstyle='italic', color='white')
        ax.tick_params(axis='x', colors='white')
        ax.tick_params(axis='y', colors='white')

        # Save the updated graph
        graph_path = os.path.join(self.submissions_folder, "temp_graph.png")
        plt.savefig(graph_path, facecolor='#2D2D2D')
        plt.close(fig)

        # Update the QPixmap in the canvas
        pixmap = QPixmap(graph_path)
        canvas.setPixmap(pixmap)

    def create_previous_submissions_view(self):
        # Create a QWidget for previous submissions view
        previous_widget = QWidget()

        # Create a layout for the previous submissions view
        layout = QVBoxLayout()
        self.previous_submissions_list = QListWidget()
        self.previous_submissions_list.addItems(self.submitted_files)  # Add the submitted files to the list
        layout.addWidget(self.previous_submissions_list)

        # Create a button to go back to the main view
        back_button = QPushButton("Back to Main")
        back_button.clicked.connect(self.switch_to_main_view)
        layout.addWidget(back_button)

        previous_widget.setLayout(layout)
        return previous_widget

    def switch_to_previous_submissions_view(self):
        self.stacked_widget.setCurrentWidget(self.previous_submissions_view)

    def switch_to_main_view(self):
        self.stacked_widget.setCurrentWidget(self.main_view)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SystemEvaluationApp()
    window.show()
    sys.exit(app.exec())

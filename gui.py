from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QVBoxLayout, QFileDialog, QHBoxLayout, QListWidget, QStackedWidget, QScrollArea
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QPalette, QColor, QFont
import shutil
import sys
import os
import average as avg
import matplotlib.pyplot as plt

class SystemEvaluationApp(QWidget):
    def __init__(self):
        super().__init__()

        # Create the submissions folder if it doesn't exist
        self.submissions_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'submissions')
        if not os.path.exists(self.submissions_folder):
            os.makedirs(self.submissions_folder)

        # Initialize the submitted_files list before calling any methods that use it
        self.submitted_files = self.load_submissions()  # Load previously submitted files

        # Set window title and size
        self.setWindowTitle("System Evaluation App")
        self.setFixedSize(900, 500)  # Increased canvas width

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
        self.view_previous_button.setFixedSize(415, 40)  # Set same size for all buttons
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
        # Initialize scores to zero
        base_scores = [0, 0, 0]  # For Base Score, Impact Score, Exploitability Score
        base_labels = ["Base Score", "Impact Score", "Exploitability Score"]
        self.add_bar_graph(layout, base_scores, base_labels, "Base Scores")

        # Temporal score bar graph
        temporal_score = [0]  # For Temporal Score
        temporal_labels = ["Temporal Score"]
        self.add_bar_graph(layout, temporal_score, temporal_labels, "Temporal Scores")

        # Environmental score bar graph
        environmental_scores = [0]  # For Environmental Score
        environmental_labels = ["Environmental Score"]
        self.add_bar_graph(layout, environmental_scores, environmental_labels, "Environmental Scores")

        # Overall CVSS score bar graph
        overall_score = [0]  # For Overall CVSS Score
        overall_labels = ["Overall CVSS Score"]
        self.add_bar_graph(layout, overall_score, overall_labels, "Overall CVSS Score")

    def add_bar_graph(self, layout, scores, labels, title):
        """Add a bar graph to the layout."""
        fig, ax = plt.subplots()
        ax.bar(labels, scores, color='blue')
        ax.set_ylim(0, 10)  # Set y-axis limit from 0.0 to 10.0
        ax.set_title(title)
        ax.set_xlabel('Metrics')
        ax.set_ylabel('Scores')

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
        self.back_button = QPushButton("Back to Main View")
        self.back_button.setFont(self.font)
        self.back_button.clicked.connect(self.switch_to_main_view)

        # Add all components to the layout
        layout.addWidget(self.filter_button_alpha)
        layout.addWidget(self.filter_button_score)
        layout.addWidget(scroll_area)
        layout.addWidget(self.download_button)
        layout.addWidget(self.delete_button)
        layout.addWidget(self.back_button)

        # Set layout for the previous submissions widget
        previous_submissions_widget.setLayout(layout)

        return previous_submissions_widget

    def open_file_dialog(self):
        """Open a file dialog to select a file."""
        file_name, _ = QFileDialog.getOpenFileName(self, "Select a File", "", "All Files (*)")
        if file_name:
            self.selected_file = file_name
            self.file_name_label.setText(os.path.basename(file_name))

    def submit_file(self):
        """Handle file submission and scoring."""
        if self.selected_file:
            # Call the function to score the file
            base_score, impact_score, exploitability_score, temporal_score, environmental_score, overall_score = avg.score_file(self.selected_file)

            # Update bar graphs with new scores
            self.update_bar_graphs(base_score, impact_score, exploitability_score, temporal_score, environmental_score, overall_score)

            # Store the submitted file
            self.store_submitted_file(self.selected_file)

            # Update the score label with the results
            self.score_label.setText(f"Scores - Base: {base_score}, Impact: {impact_score}, Exploitability: {exploitability_score}, Temporal: {temporal_score}, Environmental: {environmental_score}, Overall: {overall_score}")
        else:
            self.label.setText("No file selected. Please select a file first.")

    def update_bar_graphs(self, base_score, impact_score, exploitability_score, temporal_score, environmental_score, overall_score):
        """Update the bar graphs with new scores."""
        print(f"Updated Scores - Base: {base_score}, Impact: {impact_score}, Exploitability: {exploitability_score}, Temporal: {temporal_score}, Environmental: {environmental_score}, Overall: {overall_score}")

        # Logic to refresh the bar graphs with the new scores
        # You might need to clear existing graphs and re-create them or directly update the existing ones

    def load_submissions(self):
        """Load previously submitted files."""
        if os.path.exists(self.submissions_folder):
            return os.listdir(self.submissions_folder)
        return []

    def store_submitted_file(self, file_path):
        """Store the submitted file in the submissions folder."""
        file_name = os.path.basename(file_path)
        destination = os.path.join(self.submissions_folder, file_name)
        shutil.copy(file_path, destination)

    def update_previous_submissions_view(self):
        """Update the previous submissions view."""
        self.list_widget.clear()
        for file_name in self.submitted_files:
            self.list_widget.addItem(file_name)

    def toggle_filter_alpha(self):
        """Toggle the filter for alphabetical ordering."""
        self.filter_state_alpha = 1 - self.filter_state_alpha  # Toggle between 0 and 1
        if self.filter_state_alpha:
            self.submitted_files.sort()
        else:
            self.submitted_files = self.load_submissions()  # Reload unsorted files
        self.update_previous_submissions_view()

    def toggle_filter_score(self):
        """Toggle the filter for score ordering."""
        self.filter_state_score = 1 - self.filter_state_score  # Toggle between 0 and 1
        # Add logic for filtering by score if needed
        self.update_previous_submissions_view()

    def switch_to_previous_submissions_view(self):
        """Switch to the previous submissions view."""
        self.stacked_widget.setCurrentIndex(1)

    def switch_to_main_view(self):
        """Switch to the main view."""
        self.stacked_widget.setCurrentIndex(0)

    def download_file(self):
        """Download the selected file from previous submissions."""
        selected_items = self.list_widget.selectedItems()
        if selected_items:
            selected_file = selected_items[0].text()
            source = os.path.join(self.submissions_folder, selected_file)
            destination, _ = QFileDialog.getSaveFileName(self, "Save File", selected_file)
            if destination:
                shutil.copy(source, destination)

    def delete_file(self):
        """Delete the selected submission from the list."""
        selected_items = self.list_widget.selectedItems()
        if selected_items:
            selected_file = selected_items[0].text()
            os.remove(os.path.join(self.submissions_folder, selected_file))
            self.submitted_files.remove(selected_file)
            self.update_previous_submissions_view()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SystemEvaluationApp()
    window.show()
    sys.exit(app.exec())

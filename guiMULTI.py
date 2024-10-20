from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QSpacerItem, QSizePolicy, QPushButton, QProgressBar, QVBoxLayout, QFileDialog, QHBoxLayout, QListWidget, QMessageBox, QStackedWidget, QScrollArea
)
from PySide6.QtCore import Qt, QTimer, QSize, QThread, Signal, QObject
from PySide6.QtGui import QPalette, QColor, QFont, QIcon, QMovie
import shutil
import sys
import os
import csv
import matplotlib.pyplot as plt
import hashlib  # For hashing the CSV file
import threading
import time
from get_nvd_data import main as get_nvd_data_main
from average_nvd_data import main as average_nvd_data_main
from scoremath import *
import scoremath as sm
from analysisorchestration import *
import analysisorchestration as ao
from LLamaPPP import get_security_scores
import subprocess
import datetime
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas


class Worker(QObject):
    # Signal to send results back to the main thread
    results_ready = Signal(object)

    def __init__(self, selected_cfd, selected_cfm, selected_dv, selected_sum, selected_nvd, selected_groq):
        super().__init__()
        self.selected_cfd = selected_cfd
        self.selected_cfm = selected_cfm
        self.selected_dv = selected_dv
        self.selected_sum = selected_sum
        self.selected_nvd = selected_nvd
        self.selected_groq = selected_groq

    def run(self):
        try:
            base, impact_sub, exploitability_sub, physical, personnel, policies, average, apt = ao.main(
                self.selected_cfd,
                self.selected_cfm,
                self.selected_dv,
                self.selected_sum,
                self.selected_nvd,
                self.selected_groq  # Ensure these are passed
            )
            self.results_ready.emit((base, impact_sub, exploitability_sub, physical, personnel, policies, average, apt))
        except Exception as e:
            print(f"Error during orchestration: {e}")  # Log the exception message
            self.results_ready.emit(None)

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)



class SystemEvaluationApp(QWidget):
    def __init__(self):
        super().__init__()

        # Initialize the submitted_files list before calling any methods that use it
        self.submitted_files = self.load_submissions()

        icon_path = resource_path("files\\logo.ico")  # Use resource_path to load icon
        self.setWindowIcon(QIcon(icon_path))

        # Set window title and size
        self.setWindowTitle("ACRES")
        

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
        self.label = QLabel("Please submit files (PDF, TXT, CSV, JSON):")
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
        self.file_button.setFixedSize(406, 40)
        self.file_button.clicked.connect(self.switch_to_file_select_view)
        button_layout.addWidget(self.file_button)

        button_layout.setAlignment(Qt.AlignLeft)
        v_button_layout = QVBoxLayout()
        self.view_previous_button = QPushButton("View Previous Submissions")
        self.view_previous_button.setFont(self.font)
        self.view_previous_button.setFixedSize(406, 40)
        self.view_previous_button.clicked.connect(self.switch_to_previous_submissions_view)
        v_button_layout.addWidget(self.view_previous_button)

        layout.addLayout(button_layout)
        layout.addLayout(v_button_layout)

        # Create layout for bar graphs
        bar_graph_layout = QHBoxLayout()

        self.figures = {}
        self.create_bar_graphs(bar_graph_layout)
        
        # Add the bar graphs to the main layout
        layout.addLayout(bar_graph_layout)

        # Create a separate layout for the "Download Report" button
        button_layout = QHBoxLayout()

        self.download_report_button = QPushButton("Download Report")
        self.download_report_button.setFont(self.font)
        self.download_report_button.setFixedSize(200, 40)
        self.download_report_button.setStyleSheet("background-color: green; color: white;")
        self.download_report_button.setVisible(False)  # Initially hidden
        self.download_report_button.clicked.connect(self.download_file)

        # Add the button to its own layout and center it
        button_layout.addWidget(self.download_report_button)
        button_layout.setAlignment(Qt.AlignCenter)

        # Add the button layout below the bar graphs
        layout.addLayout(button_layout)

        layout.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        main_widget.setLayout(layout)

        return main_widget



    def create_bar_graphs(self, layout):
        self.figures = {}
        self.figures['base'] = self.add_bar_graph(layout, [0, 0, 0], ["Base"], "Impact Metrics (CVSS)", (6, 4))
        #self.figures['temporal'] = self.add_bar_graph(layout, [0], ["Temporal"], "Temporal Scores", (4, 4))
        #self.figures['environmental'] = self.add_bar_graph(layout, [0], ["Environmental"], "Environmental Score", (4, 4))
        self.figures['security'] = self.add_bar_graph(layout, [0, 0, 0], ["Physical Security", "Personnel", "Policies"], "Security Best Practices Scores", (6, 4), y_limit=(0, 1))  # Set y limit to 0-1
        self.figures['overall'] = self.add_bar_graph(layout, [0], ["Environment", "APT Threat Index"], "Adjusted Score", (4, 4))

    
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
        self.download_button = QPushButton("Download Selected Report")
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
        toplayout = QHBoxLayout()
        leftlayout = QVBoxLayout()
        rightlayout = QVBoxLayout()
        bottomlayout = QHBoxLayout()

        # Create throbber
        self.throbber_label = QLabel(self)
        self.throbber_movie = QMovie("files/throbbergif.gif")
        self.throbber_label.setMovie(self.throbber_movie)
        self.throbber_label.setAlignment(Qt.AlignLeft)
        throbber_size = QSize(50, 50)  # Set the size to make the GIF smaller
        self.throbber_movie.setScaledSize(throbber_size)
        self.throbber_label.setVisible(False)
        #self.throbber_movie.start()

        # Text field for submission name
        self.submission_name_input = QLineEdit()
        self.submission_name_input.setPlaceholderText("Enter submission name")
        self.submission_name_input.setFont(self.font)
        self.submission_name_input.setStyleSheet("color: white; background-color: #3E3E3E;")
        toplayout.addWidget(self.submission_name_input)

        # Add throbber to layout
        toplayout.addWidget(self.throbber_label)

        self.cfd_file_name_label = QLabel("")
        self.cfd_file_name_label.setFont(self.font)
        self.cfd_file_name_label.setStyleSheet("color: white;")
        self.cfd_file_name_label.setAlignment(Qt.AlignLeft)
        self.cfd_file_name_label.setWordWrap(True)
        self.cfd_file_name_label.setFixedWidth(400)

        self.cfm_file_name_label = QLabel("")
        self.cfm_file_name_label.setFont(self.font)
        self.cfm_file_name_label.setStyleSheet("color: white;")
        self.cfm_file_name_label.setAlignment(Qt.AlignLeft)
        self.cfm_file_name_label.setWordWrap(True)
        self.cfm_file_name_label.setFixedWidth(400)

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

        self.nvd_file_name_label = QLabel("")
        self.nvd_file_name_label.setFont(self.font)
        self.nvd_file_name_label.setStyleSheet("color: white;")
        self.nvd_file_name_label.setAlignment(Qt.AlignLeft)
        self.nvd_file_name_label.setWordWrap(True)
        self.nvd_file_name_label.setFixedWidth(400)

        self.groq_file_name_label = QLabel("")
        self.groq_file_name_label.setFont(self.font)
        self.groq_file_name_label.setStyleSheet("color: white;")
        self.groq_file_name_label.setAlignment(Qt.AlignLeft)
        self.groq_file_name_label.setWordWrap(True)
        self.groq_file_name_label.setFixedWidth(400)

        # Create a button to go back to the main view
        self.back_button = QPushButton("Back to Main Menu")
        self.back_button.setFont(self.font)
        self.back_button.setFixedSize(200, 30)  # Half the original size
        self.back_button.clicked.connect(self.switch_to_main_view)


        self.label2 = QLabel("Please submit a file for Critical Functions Definitions (CSV, JSON):")
        self.label2.setFont(self.font)
        self.label2.setStyleSheet("color: white;")
        self.label2.setAlignment(Qt.AlignLeft | Qt.AlignTop)

        self.select_cfd_button = QPushButton("Select File")
        self.select_cfd_button.setFont(self.font)
        self.select_cfd_button.setFixedSize(203, 30)  # Half the original size
        self.select_cfd_button.clicked.connect(lambda: self.open_file_dialog("cfd"))

        self.label22 = QLabel("Please submit a file for Critical Functions Mapping (CSV, JSON):")
        self.label22.setFont(self.font)
        self.label22.setStyleSheet("color: white;")
        self.label22.setAlignment(Qt.AlignLeft | Qt.AlignTop)

        self.select_cfm_button = QPushButton("Select File")
        self.select_cfm_button.setFont(self.font)
        self.select_cfm_button.setFixedSize(203, 30)  # Half the original size
        self.select_cfm_button.clicked.connect(lambda: self.open_file_dialog("cfm"))

        self.label3 = QLabel("Please submit a file for Detected Vulnerabilities (CSV, JSON):")
        self.label3.setFont(self.font)
        self.label3.setStyleSheet("color: white;")
        self.label3.setAlignment(Qt.AlignLeft | Qt.AlignTop)

        self.select_dv_button = QPushButton("Select File")
        self.select_dv_button.setFont(self.font)
        self.select_dv_button.setFixedSize(203, 30)  # Half the original size
        self.select_dv_button.clicked.connect(lambda: self.open_file_dialog("dv"))

        # self.label4 = QLabel("Please submit a file for Hardware (CSV, JSON):")
        # self.label4.setFont(self.font)
        # self.label4.setStyleSheet("color: white;")
        # self.label4.setAlignment(Qt.AlignLeft | Qt.AlignTop)

        # self.select_h_button = QPushButton("Select File")
        # self.select_h_button.setFont(self.font)
        # self.select_h_button.setFixedSize(203, 30)  # Half the original size
        # self.select_h_button.clicked.connect(lambda: self.open_file_dialog("h"))

        # self.label5 = QLabel("Please submit a file for Software (CSV, JSON):")
        # self.label5.setFont(self.font)
        # self.label5.setStyleSheet("color: white;")
        # self.label5.setAlignment(Qt.AlignLeft | Qt.AlignTop)

        # self.select_s_button = QPushButton("Select File")
        # self.select_s_button.setFont(self.font)
        # self.select_s_button.setFixedSize(203, 30)  # Half the original size
        # self.select_s_button.clicked.connect(lambda: self.open_file_dialog("s"))

        self.label6 = QLabel("Please submit a file for Summaries (CSV, JSON):")
        self.label6.setFont(self.font)
        self.label6.setStyleSheet("color: white;")
        self.label6.setAlignment(Qt.AlignLeft | Qt.AlignTop)

        self.select_sum_button = QPushButton("Select File")
        self.select_sum_button.setFont(self.font)
        self.select_sum_button.setFixedSize(203, 30)  # Half the original size
        self.select_sum_button.clicked.connect(lambda: self.open_file_dialog("sum"))

        self.label7 = QLabel("Please submit a file for the NVD API Key (TXT):")
        self.label7.setFont(self.font)
        self.label7.setStyleSheet("color: white;")
        self.label7.setAlignment(Qt.AlignLeft | Qt.AlignTop)

        self.select_nvd_button = QPushButton("Select File")
        self.select_nvd_button.setFont(self.font)
        self.select_nvd_button.setFixedSize(203, 30)  # Half the original size
        self.select_nvd_button.clicked.connect(lambda: self.open_file_dialog("nvd"))

        self.label8 = QLabel("Please submit a file for the Groq API Key (TXT):")
        self.label8.setFont(self.font)
        self.label8.setStyleSheet("color: white;")
        self.label8.setAlignment(Qt.AlignLeft | Qt.AlignTop)

        self.select_groq_button = QPushButton("Select File")
        self.select_groq_button.setFont(self.font)
        self.select_groq_button.setFixedSize(203, 30)  # Half the original size
        self.select_groq_button.clicked.connect(lambda: self.open_file_dialog("groq"))

        self.submit_button = QPushButton("Submit File")
        self.submit_button.setFont(self.font)
        self.submit_button.setFixedSize(200, 30)
        self.submit_button.clicked.connect(self.submit_file)

        # Add labels and buttons to the layout

        leftlayout.addWidget(self.label2)
        leftlayout.addWidget(self.cfd_file_name_label)
        leftlayout.addWidget(self.select_cfd_button)
        leftlayout.addStretch()  # Optional: Add stretchable space to separate sections

        rightlayout.addWidget(self.label22)
        rightlayout.addWidget(self.cfm_file_name_label)
        rightlayout.addWidget(self.select_cfm_button)
        rightlayout.addStretch()  # Optional: Add stretchable space to separate sections

        leftlayout.addWidget(self.label3)
        leftlayout.addWidget(self.dv_file_name_label)
        leftlayout.addWidget(self.select_dv_button)
        leftlayout.addStretch()  # Optional: Add stretchable space to separate sections

        # rightlayout.addWidget(self.label4)
        # rightlayout.addWidget(self.h_file_name_label)
        # rightlayout.addWidget(self.select_h_button)
        # rightlayout.addStretch()  # Optional: Add stretchable space to separate sections

        # leftlayout.addWidget(self.label5)
        # leftlayout.addWidget(self.s_file_name_label)
        # leftlayout.addWidget(self.select_s_button)
        # leftlayout.addStretch()  # Optional: Add stretchable space to separate sections

        rightlayout.addWidget(self.label6)
        rightlayout.addWidget(self.sum_file_name_label)
        rightlayout.addWidget(self.select_sum_button)
        rightlayout.addStretch()  # Optional: Add stretchable space to separate sections

        leftlayout.addWidget(self.label7)
        leftlayout.addWidget(self.nvd_file_name_label)
        leftlayout.addWidget(self.select_nvd_button)
        leftlayout.addStretch()  # Optional: Add stretchable space to separate sections

        rightlayout.addWidget(self.label8)
        rightlayout.addWidget(self.groq_file_name_label)
        rightlayout.addWidget(self.select_groq_button)
        rightlayout.addStretch()  # Optional: Add stretchable space to separate sections

        # Add the submit button without additional spacing
        bottomlayout.addWidget(self.submit_button)
        bottomlayout.addWidget(self.back_button)



        # Set the layout for the previous submissions widget
        hbox = QHBoxLayout()
        hbox.addLayout(leftlayout)
        hbox.addLayout(rightlayout)

        mainlayout = QVBoxLayout()
        mainlayout.addLayout(toplayout)
        mainlayout.addLayout(hbox)
        mainlayout.addLayout(bottomlayout)

        #file_select_widget.setLayout(toplayout)
        file_select_widget.setLayout(mainlayout)

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
            if file_type == "cfd":
                self.selected_cfd_button = selected_file
                self.cfd_file_name_label.setText(f"Selected: {file_name}")
            if file_type == "cfm":
                self.selected_cfm_button = selected_file
                self.cfm_file_name_label.setText(f"Selected: {file_name}")
            elif file_type == "dv":
                self.selected_dv_button = selected_file
                self.dv_file_name_label.setText(f"Selected: {file_name}")
            # elif file_type == "h":
            #     self.selected_h_button = selected_file
            #     self.h_file_name_label.setText(f"Selected: {file_name}")
            # elif file_type == "s":
            #     self.selected_s_button = selected_file
            #     self.s_file_name_label.setText(f"Selected: {file_name}")
            elif file_type == "sum":
                self.selected_sum_button = selected_file
                self.sum_file_name_label.setText(f"Selected: {file_name}")
            elif file_type == "nvd":
                self.selected_nvd_button = selected_file
                self.nvd_file_name_label.setText(f"Selected: {file_name}")
            elif file_type == "groq":
                self.selected_groq_button = selected_file
                self.groq_file_name_label.setText(f"Selected: {file_name}")

    def start_throbber(self):
        print("starting throbber")
        self.throbber_label.setVisible(True)
        self.throbber_movie.start()
        self.layout().update()  # Force layout update

    def stop_throbber(self):
        self.throbber_movie.stop()
        self.throbber_label.setVisible(False)
        self.layout().update()  # Force layout update

        
    def process_results(self, results):
        self.stop_throbber()  # Stop throbber when processing results
        if results is not None:
            base, impact_sub, exploitability_sub, physical, personnel, policies, average, apt = results
            print("Results:", base, impact_sub, exploitability_sub, physical, personnel, policies, average, apt)
            
            # Show success message and update GUI
            self.score_label.setText(f"Files submitted successfully! Score: {average}, {apt}")

            # Store submission details and update view
            submission_name = self.submission_name_input.text().strip() or "Unnamed"
            current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.submitted_files.append((submission_name, current_time, average, apt))
            self.save_submissions()
            self.update_previous_submissions_view()

            # Update bar graphs with the calculated scores
            self.update_bar_graph('base', [base])
            self.update_bar_graph('security', [physical, personnel, policies])
            self.update_bar_graph('overall', [average, apt])

            # Reset file selections and show the download report button
            self.reset_file_selections()
            self.download_report_button.setVisible(True)
        else:
            print("Task failed or returned no results.")
        
        

    def submit_file(self):
        self.start_throbber()
        # Check for required files
        if not self.selected_cfd_button or not self.selected_cfm_button or not self.selected_dv_button or not self.selected_sum_button or not self.selected_nvd_button or not self.selected_groq_button:
            missing_files = []
            if not self.selected_cfd_button:
                missing_files.append("Critical Functions Definitions")
            if not self.selected_cfm_button:
                missing_files.append("Critical Functions Mapping")
            if not self.selected_dv_button:
                missing_files.append("Detected Vulnerabilities")
            if not self.selected_sum_button:
                missing_files.append("Summaries")
            if not self.selected_nvd_button:
                missing_files.append("NVD")
            if not self.selected_groq_button:
                missing_files.append("Groq")

            QMessageBox.warning(self, "Missing Files", "Please select the following required files:\n" + "\n".join(missing_files))
            self.stop_throbber()  # Stop the throbber if files are missing
            return  # Exit if files are missing

        # Prepare files to submit
        files_to_submit = {
            "cfd": self.selected_cfd_button,
            "cfm": self.selected_cfm_button,
            "dv": self.selected_dv_button,
            "sum": self.selected_sum_button,
            "nvd": self.selected_nvd_button,
            "groq": self.selected_groq_button,
        }

        worker = Worker(
        self.selected_cfd_button,
        self.selected_cfm_button,
        self.selected_dv_button,
        self.selected_sum_button,
        self.selected_nvd_button,
        self.selected_groq_button
        )

        # Connect the signal to process_results
        worker.results_ready.connect(self.process_results)

        # Start the orchestration in a separate thread
        threading.Thread(target=worker.run).start()

    def reset_file_selections(self):
        # Clear the selections for all file types
        self.selected_cf_file = None
        self.selected_dv_file = None
        # self.selected_h_file = None
        # self.selected_s_file = None
        self.selected_sum_file = None
        self.selected_nvd_file = None
        self.selected_groq_file = None
        
        # Clear the labels in the UI
        self.cfd_file_name_label.setText("")
        self.cfm_file_name_label.setText("")
        self.dv_file_name_label.setText("")
        # self.h_file_name_label.setText("")
        # self.s_file_name_label.setText("")
        self.sum_file_name_label.setText("")
        self.nvd_file_name_label.setText("")
        self.groq_file_name_label.setText("")

    def update_previous_submissions_view(self):
        # Clear and update the list widget in the previous submissions view
        self.list_widget.clear()

        # Use the current state of self.submitted_files to display the filtered submissions
        for file_name, submission_time, score in self.submitted_files:
            self.list_widget.addItem(f"{file_name} - {submission_time} - Score: {score}")  # Add formatted string

    def toggle_filter_alpha(self):
        # Toggle the alphabetical filtering state
        if self.filter_state_alpha == 0:
            # Apply alphabetical filter (ascending)
            self.submitted_files = sorted(self.submitted_files, key=lambda x: x[0])  # Sort by file name
            self.filter_state_alpha = 1
        elif self.filter_state_alpha == 1:
            # Apply alphabetical filter (descending)
            self.submitted_files = sorted(self.submitted_files, key=lambda x: x[0], reverse=True)  # Sort by file name
            self.filter_state_alpha = 2
        else:
            # Reset alphabetical filter
            self.submitted_files = self.load_submissions()  # Reload submissions to reset
            self.filter_state_alpha = 0
        self.update_previous_submissions_view()  # Update the view after filtering

    def toggle_filter_score(self):
        # Toggle the score filtering state
        if self.filter_state_score == 0:
            # Apply score filter (ascending)
            self.submitted_files = sorted(self.submitted_files, key=lambda x: float(x[2]))  # Sort by score
            self.filter_state_score = 1
        elif self.filter_state_score == 1:
            # Apply score filter (descending)
            self.submitted_files = sorted(self.submitted_files, key=lambda x: float(x[2]), reverse=True)  # Sort by score
            self.filter_state_score = 2
        else:
            # Reset score filter
            self.submitted_files = self.load_submissions()  # Reload submissions to reset
            self.filter_state_score = 0
        self.update_previous_submissions_view()  # Update the view after filtering


    def delete_file(self):
        # Delete the selected file from the list and submissions folder
        selected_items = self.list_widget.selectedItems()
        if selected_items:
            selected_item = selected_items[0].text()
            # Extract parts of the selected item based on your current formatting
            parts = selected_item.split(" - ")
            if len(parts) == 3:  # Ensure it has three parts
                file_name, submission_time, score = parts[0], parts[1], parts[2].replace("Score: ", "").strip()

                # Find the exact index of the selected submission in the submitted_files list
                for index, (f, t, s) in enumerate(self.submitted_files):
                    if f == file_name and t == submission_time and float(s) == float(score):  # Compare as floats for consistency
                        # Remove the selected submission
                        del self.submitted_files[index]
                        break  # Stop after deleting the selected submission

                # Save the updated submission list back to the CSV
                self.save_submissions()

                # Update the list view
                self.update_previous_submissions_view()

                print(f"Submission {file_name} from {submission_time} with score {score} has been deleted.")
            else:
                print("Selected item does not match the expected format.")

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
        # Save the submitted files, submission time, and scores to a CSV file
        with open("submissions.csv", "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            
            # Write header for the CSV file
            writer.writerow(["File Name", "Submission Time", "Environment Score", "APT Score"])  # Updated header
            
            # Write the submitted files and their details
            for file_name, submission_time, env_score, apt_score in self.submitted_files:  # Unpack three items
                writer.writerow([file_name, submission_time, env_score, apt_score])  # Write the three columns

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
                next(reader)  # Skip header row
                for row in reader:
                    if len(row) == 3:  # Ensure the row has three items
                        submissions.append((row[0], row[1], row[2], row[3]))  # (File name, Submission Time, Score)
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

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SystemEvaluationApp()
    app.setWindowIcon(QIcon("files/logo.ico"))
    window.show()  # Show the window first
    window.showMaximized()  # Then maximize it
    sys.exit(app.exec())

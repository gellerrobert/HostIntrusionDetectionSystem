import tkinter as tk
from tkinter import font


def create_gradient(canvas, width, height, color1, color2):
    """Create a vertical gradient filling the entire canvas"""
    r1, g1, b1 = canvas.winfo_rgb(color1)
    r2, g2, b2 = canvas.winfo_rgb(color2)
    r_ratio = float(r2 - r1) / height
    g_ratio = float(g2 - g1) / height
    b_ratio = float(b2 - b1) / height

    for i in range(height):
        nr = int(r1 + (r_ratio * i))
        ng = int(g1 + (g_ratio * i))
        nb = int(b1 + (b_ratio * i))
        color = "#%4.4x%4.4x%4.4x" % (nr, ng, nb)
        canvas.create_line(0, i, width, i, fill=color)


def generateApp(uploadFile, triggerScan):
    # Create the main window
    root = tk.Tk()
    root.title("Host Intrusion Detection System")
    root.geometry("800x500")
    # Create a canvas for the gradient background and add it to the window
    canvas = tk.Canvas(root, height=500, width=800)
    canvas.pack(fill="both", expand=True)
    # Create a gradient background with more solid colors
    create_gradient(canvas, 800, 500, "#004d00", "#001a4d")  # Dark green to dark blue
    # Create custom font
    custom_font = font.Font(family="Helvetica", size=12, weight="bold")
    # Create an upload button with contrasting colors on the canvas
    upload_button = tk.Button(canvas, text="Upload File", command=uploadFile, foreground="white", background="black")
    upload_button_window = canvas.create_window(400, 150, window=upload_button)
    # Create a scan button with contrasting colors on the canvas
    action_button = tk.Button(canvas, text="Scan File", command=triggerScan, foreground="white",
                              background="black", font=custom_font)
    action_button_window = canvas.create_window(400, 250, window=action_button)
    # Start the GUI event loop
    root.mainloop()

import pymupdf
import os

pdf_path = "Dashboard-Screenshots.pdf"
output_folder = "screenshots"

os.makedirs(output_folder, exist_ok=True)

pdf = pymupdf.open(pdf_path)

print(f"Total PDF pages: {len(pdf)}")

for i, page in enumerate(pdf):
    pix = page.get_pixmap(matrix=pymupdf.Matrix(2, 2))
    image_path = os.path.join(
        output_folder,
        f"dashboard-{i+1}.png"
    )
    pix.save(image_path)
    print(f"Extracted: dashboard-{i+1}.png")

pdf.close()

print("\nAll dashboard screenshots extracted successfully!")
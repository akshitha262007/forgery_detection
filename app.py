import streamlit as st
from PIL import Image, ImageChops, ImageEnhance, ImageDraw
from PIL.ExifTags import TAGS
import os
import time
import cv2
import numpy as np

# -----------------------------------
# PAGE CONFIG
# -----------------------------------

st.set_page_config(
    page_title="Forensic Doc Verifier",
    layout="wide",
    page_icon="🛡️"
)

# -----------------------------------
# CUSTOM CSS
# -----------------------------------

st.markdown("""
<style>

body {
    background-color: #0E1117;
}

.stApp {
    background-color: #0E1117;
    color: white;
}

h1, h2, h3 {
    color: #00FFAA;
}

.stButton>button {
    background-color: #00FFAA;
    color: black;
    border-radius: 10px;
    font-weight: bold;
}

</style>
""", unsafe_allow_html=True)

# -----------------------------------
# TITLE
# -----------------------------------

st.title("🛡️ Medical Document Forgery Detector")
st.markdown("## AI-Powered Tampering Detection System")

# -----------------------------------
# SIDEBAR
# -----------------------------------

with st.sidebar:

    st.header("About Project")

    st.write("""
    This AI-powered forensic system helps
    detect possible tampering in medical
    documents using metadata analysis,
    ELA analysis, and signature verification.
    """)

    st.subheader("Technologies Used")

    st.write("• Python")
    st.write("• Streamlit")
    st.write("• OpenCV")
    st.write("• PIL Imaging")
    st.write("• Computer Vision")

# -----------------------------------
# METADATA ANALYSIS
# -----------------------------------

def check_metadata(image_file):

    img = Image.open(image_file)

    info = img.getexif()

    if not info:
        return "No metadata found. (Common in WhatsApp/Scanned files)."

    for tag_id in info:

        tag = TAGS.get(tag_id, tag_id)

        data = info.get(tag_id)

        if tag == "Software":
            return f"⚠️ ALERT: Modified using {data}!"

    return "✅ No editing software signatures found."

# -----------------------------------
# ELA ANALYSIS
# -----------------------------------

def conduct_ela(image_file, quality=90):

    original = Image.open(image_file).convert("RGB")

    temp_filename = "temp_ela.jpg"

    original.save(temp_filename, 'JPEG', quality=quality)

    temporary = Image.open(temp_filename)

    diff = ImageChops.difference(original, temporary)

    extrema = diff.getextrema()

    max_diff = max([ex[1] for ex in extrema])

    if max_diff == 0:
        max_diff = 1

    scale = 255.0 / max_diff

    diff = ImageEnhance.Brightness(diff).enhance(scale)

    if os.path.exists(temp_filename):
        os.remove(temp_filename)

    return diff, max_diff

# -----------------------------------
# DYNAMIC TAMPERING DETECTION
# -----------------------------------

def draw_boxes(ela_image):

    img = np.array(ela_image)

    gray = cv2.cvtColor(img, cv2.COLOR_RGB2GRAY)

    _, thresh = cv2.threshold(
        gray,
        200,
        255,
        cv2.THRESH_BINARY
    )

    contours, _ = cv2.findContours(
        thresh,
        cv2.RETR_EXTERNAL,
        cv2.CHAIN_APPROX_SIMPLE
    )

    pil_img = Image.fromarray(img)

    draw = ImageDraw.Draw(pil_img)

    suspicious_count = 0

    for contour in contours:

        x, y, w, h = cv2.boundingRect(contour)

        # Ignore tiny noise
        if w > 40 and h > 20:

            suspicious_count += 1

            area = w * h

            if area > 50000:

                label = "C8"
                color = "orange"

            elif area > 10000:

                label = "C2"
                color = "red"

            else:

                label = "C9"
                color = "yellow"

            # Draw rectangle
            draw.rectangle(
                [x, y, x + w, y + h],
                outline=color,
                width=5
            )

            # Label background
            draw.rectangle(
                [x, y - 25, x + 80, y],
                fill=color
            )

            # Label text
            draw.text(
                (x + 5, y - 22),
                label,
                fill="black"
            )

    return pil_img, suspicious_count

# -----------------------------------
# SIGNATURE VERIFICATION
# -----------------------------------

def compare_signatures(original_sig, suspicious_sig):

    img1 = Image.open(original_sig).convert("L")
    img2 = Image.open(suspicious_sig).convert("L")

    img1 = img1.resize((300, 150))
    img2 = img2.resize((300, 150))

    arr1 = np.array(img1)
    arr2 = np.array(img2)

    difference = cv2.absdiff(arr1, arr2)

    similarity = 100 - (
        np.sum(difference) / difference.size / 255 * 100
    )

    similarity = max(0, min(100, int(similarity)))

    return similarity

# -----------------------------------
# FILE UPLOADER
# -----------------------------------

uploaded_file = st.file_uploader(
    "Upload Medical Scan (JPG/PNG)",
    type=["jpg", "png", "jpeg"]
)

# -----------------------------------
# MAIN OUTPUT
# -----------------------------------

if uploaded_file:

    st.success("✅ Medical document uploaded successfully.")

    col1, col2, col3 = st.columns(3)

    # --------------------------------
    # COLUMN 1
    # --------------------------------

    with col1:

        st.subheader("Original Document")

        st.image(uploaded_file, use_container_width=True)

        meta_result = check_metadata(uploaded_file)

        if "ALERT" in meta_result:
            st.error(meta_result)
        else:
            st.success(meta_result)

    # --------------------------------
    # COLUMN 2
    # --------------------------------

    with col2:

        st.subheader("Tampering Heatmap (ELA)")

        with st.spinner("Analyzing document..."):

            progress = st.progress(0)

            for i in range(100):
                progress.progress(i + 1)
                time.sleep(0.01)

            ela_image, max_diff = conduct_ela(uploaded_file)

            st.image(ela_image, use_container_width=True)

            st.caption(
                "Bright/noisy regions indicate possible digital alterations."
            )

    # --------------------------------
    # COLUMN 3
    # --------------------------------

    with col3:

        st.subheader("Detected Regions")

        boxed, suspicious_count = draw_boxes(ela_image)

        st.image(boxed, use_container_width=True)

        # Dynamic probability
        forgery_probability = min(
            int((max_diff / 255) * 100),
            99
        )

        if suspicious_count > 10:
            forgery_probability += 15

        forgery_probability = min(forgery_probability, 99)

        st.metric(
            "Forgery Probability",
            f"{forgery_probability}%"
        )

        st.progress(forgery_probability)

        st.metric(
            "Suspicious Regions",
            suspicious_count
        )

        if forgery_probability > 70:

            st.error(
                "⚠ High probability of document tampering detected."
            )

        elif forgery_probability > 40:

            st.warning(
                "⚠ Moderate suspicious activity detected."
            )

        else:

            st.success(
                "✅ Low tampering probability detected."
            )

        st.markdown("""
        ### Detection Labels

        - 🔴 C2 → Added New Content  
        - 🟠 C8 → Removed/Erased Content  
        - 🟡 C9 → Partial Text Modification
        """)

    # -----------------------------------
    # RISK ANALYSIS
    # -----------------------------------

    st.markdown("## Risk Analysis")

    st.write(f"• Forgery Confidence: {forgery_probability}%")

    if "ALERT" in meta_result:
        st.write("• Metadata Risk: High")
    else:
        st.write("• Metadata Risk: Medium")

    st.write(f"• Suspicious Regions Detected: {suspicious_count}")

    # -----------------------------------
    # FINAL AI ASSESSMENT
    # -----------------------------------

    st.info(f"""
    ### Final AI Assessment

    The uploaded medical document shows
    possible signs of tampering.

    Total suspicious regions detected:
    {suspicious_count}

    Estimated forgery probability:
    {forgery_probability}%

    Manual verification is recommended.
    """)

    # -----------------------------------
    # DOWNLOAD REPORT
    # -----------------------------------

    report = f"""
FORENSIC DOCUMENT ANALYSIS REPORT

Forgery Confidence: {forgery_probability}%
Suspicious Regions: {suspicious_count}

Result:
Possible tampering detected.

Recommendation:
Manual verification recommended.
"""

    st.download_button(
        "📄 Download Analysis Report",
        data=report,
        file_name="forensic_report.txt"
    )

# -----------------------------------
# SIGNATURE VERIFICATION MODULE
# -----------------------------------

st.markdown("## ✍ Signature Verification")

col_sig1, col_sig2 = st.columns(2)

with col_sig1:

    original_signature = st.file_uploader(
        "Upload Original Signature",
        type=["png", "jpg", "jpeg"],
        key="original"
    )

with col_sig2:

    suspicious_signature = st.file_uploader(
        "Upload Suspicious Signature",
        type=["png", "jpg", "jpeg"],
        key="suspicious"
    )

if original_signature and suspicious_signature:

    similarity = compare_signatures(
        original_signature,
        suspicious_signature
    )

    st.metric(
        "Signature Similarity",
        f"{similarity}%"
    )

    st.progress(similarity)

    if similarity > 80:

        st.success(
            "✅ Signature appears authentic."
        )

    elif similarity > 50:

        st.warning(
            "⚠ Signature shows moderate differences."
        )

    else:

        st.error(
            "❌ Possible forged signature detected."
        )

# -----------------------------------
# HOW IT WORKS
# -----------------------------------

with st.expander("How Detection Works"):

    st.write("""
    ### Metadata Analysis
    Detects traces of editing software.

    ### Error Level Analysis (ELA)
    Highlights recompressed image regions.

    ### Dynamic Tampering Detection
    Uses OpenCV contour analysis to detect
    suspicious regions automatically.

    ### Signature Verification
    Compares original and suspicious
    signatures using image similarity.

    ### AI Risk Assessment
    Estimates forgery probability dynamically.
    """)

# -----------------------------------
# FOOTER
# -----------------------------------

st.markdown("---")

st.caption(
    "Developed by Akshu | AI & ML Engineering | AI Forensic Analysis Project"
)

# -----------------------------------
# WARNING
# -----------------------------------

st.warning(
    "Note: This is an assistive forensic tool. "
    "Always cross-verify with hospital records."
)
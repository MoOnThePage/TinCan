import streamlit as st
import os

st.sidebar.title("TinCAN - Work Space")
st.sidebar.image("img.png")
st.sidebar.divider()

# Where files are saved
UPLOAD_DIR = "shared_files"
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

##################################################
#       Show files that can be downloaded        #
##################################################
files = os.listdir(UPLOAD_DIR)

if files:
    st.subheader("Download Files")

    # Display each file with download and delete buttons
    for filename in files:
        col1, col2, col3 = st.columns([3, 2, 1])

        with col1:
            st.write(f"**{filename}**")

        with col2:
            filepath = os.path.join(UPLOAD_DIR, filename)
            with open(filepath, "rb") as f:
                st.download_button(
                    label = "Download",
                    data = f,
                    file_name = filename,
                    key = f"dl_{filename}",
                )

        with col3:
            # Delete Button
            if st.button(f"🚮", key = f"del_{filename}"):
                os.remove(filepath)
                st.success(f"Deleted **{filename}**")
                st.rerun() # refresh to show updated list
else:
    st.info("No file is available yet")
st.divider()

##################################################
#               Upload a file                    #
##################################################
st.sidebar.subheader("Upload a File")
uploaded_file = st.sidebar.file_uploader("Choose a file to upload")

if uploaded_file is not None:
    # Simple save without
    filepath = os.path.join(UPLOAD_DIR, uploaded_file.name)

    # Check if the file is already exists
    if os.path.exists(filepath):
        st.warning(f"File **{uploaded_file.name}** already exists, Overwriting...")

    with open(filepath, "wb") as f:
        f.write(uploaded_file.getvalue())

    st.success(f"Uploaded **{uploaded_file.name}**")
    st.info(f"The other person can now download it. Refresh the page to see it in the list.")

    # Show download button immediately for the uploader too
    st.download_button(
        label = "Download File",
        data = uploaded_file.getvalue(),
        file_name = uploaded_file.name,
        key = "uploader_download"
    )

# Add a clear all files button (optional)
st.sidebar.divider()
if files:
    if st.sidebar.button("Clear All Files"):
        for filename in files:
            filepath = os.path.join(UPLOAD_DIR, filename)
            os.remove(filepath)
        st.success("All files deleted!")
        st.rerun()
else:
    st.info("Upload area above • Delete buttons appear next to each file")
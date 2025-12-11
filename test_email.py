import streamlit as st
import smtplib
from email.mime.text import MIMEText

st.set_page_config(
    page_title="Email Test",
    page_icon="📧",
    layout="centered"
)

st.title("📧 Email Test")
st.write("Testing: taskeenafifa934@gmail.com")

if st.button("TEST EMAIL"):
    try:
        # Your credentials
        email = "taskeenafifa934@gmail.com"
        password = "rkzi jjpi yydy ldhc"
        
        st.info("Connecting to Gmail...")
        
        # Connect and send
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(email, password)
        st.success("✅ Login successful!")
        
        # Send email
        msg = MIMEText("Test email from Threat Dashboard")
        msg["Subject"] = "✅ Email Test"
        msg["From"] = email
        msg["To"] = email
        
        server.send_message(msg)
        server.quit()
        
        st.success("✅ Email sent! Check your inbox.")
        st.balloons()
        
    except Exception as e:
        st.error(f"❌ Error: {e}")
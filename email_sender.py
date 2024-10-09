# import smtplib, ssl
# from email.mime.text import MIMEText
# from email.mime.multipart import MIMEMultipart
# from google.auth.transport.requests import Request
# from google.oauth2.credentials import Credentials
# from google_auth_oauthlib.flow import InstalledAppFlow
# from googleapiclient.discovery import build
# from googleapiclient.errors import HttpError

# def send_error(error, config):
    
#     # Create a secure SSL context
#     context = ssl.create_default_context()

#     try:
#         if config.starttls:
#             server = smtplib.SMTP(config.server,config.port)
#             server.starttls(context=context)
#         else:
#             server = smtplib.SMTP_SSL(config.server, config.port, context=context)
#         server.login(config['from'], '')
#         message = MIMEMultipart("alternative")
#         message['Subject'] = config['subject']
#         message['From'] = config['from']
#         message['To'] = config['to']
        
#         text = MIMEText(insertError(config['text'], error), 'text')
#         html = MIMEText(insertError(config['html'], error), 'html')
#         message.attach(text)
#         message.attach(html)

#         server.sendmail(config['from'], config['to'], message.as_string())
#     except Exception as e:
#         print('Error sending email')
#         print(e)
#     finally:
#         server.quit()

# def insertError(message, error):
#     return message.replace('$error', str(error))
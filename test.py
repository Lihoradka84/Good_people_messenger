import imaplib

mail = imaplib.IMAP4_SSL('imap.gmail.com')
mail.login('Lihoradka84@mail.com', 'VTqBf9wA_2020')
mail.select('inbox')
result, data = mail.search(None, 'ALL')  # Все письма
print(data)
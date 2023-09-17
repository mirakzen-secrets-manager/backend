import qrcode

otp_link = ""
q = qrcode.QRCode()
q.add_data(otp_link)
print(q.print_ascii())

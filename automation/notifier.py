import httpx
from dotenv import load_dotenv
import  httpx
import os

load_dotenv()


class Notification:
    def __init__(self):
        self.__botid = os.getenv("BOT_ID")
        self.__push_url = f"https://api.telegram.org/bot{self.__botid}/sendMessage"

    def push(self,message):
        with httpx.Client() as client:
            data = {
                "chat_id": 1273444499,
                "text": message
            }
            req = client.post(self.__push_url,json=data)
            res = req.json()
            
            if res['ok'] : print("Notification sent successfully") 
            else : print("Error while sending ",res)




if __name__ == "__main__":
    nf = Notification()
    nf.push("satender this side")





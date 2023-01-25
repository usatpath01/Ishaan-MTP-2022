docker stop flask_ishan2 && docker rm flask_ishan2
docker image build -t flask_ishan_img2 . 
docker run -dit -p 5001:5001 --name flask_ishan2 --network flask_net_overlay flask_ishan_img2
docker stop flask_ishan1 && docker rm flask_ishan1
docker image build -t flask_ishan_img1 . 
docker run -dit -p 5000:5000 --name flask_ishan1 --network flask_net_overlay flask_ishan_img1

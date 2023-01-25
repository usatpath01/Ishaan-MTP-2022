docker stop flask_ishan && docker rm flask_ishan
docker image build -t flask_ishan_img . 
docker run -dit -p 5000:5000 --name flask_ishan --network flask_net_overlay flask_ishan_img

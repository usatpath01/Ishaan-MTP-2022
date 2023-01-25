docker stop flask_smrl && docker rm flask_smrl
docker image build -t flask_smrl_img . 
docker run -dit -p 5000:5000 --name flask_smrl --network flask_net_overlay flask_smrl_img


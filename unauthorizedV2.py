import ftplib
import socket
import sys
import memcache
import pymongo
import requests
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QApplication, QWidget,  QPushButton, QFileDialog


class SecurityChecker(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle(
            'Hệ thống phát hiện lỗ hổng trái phép cổng chung v2 được thiết kế bởi Demongod')
        self.text = QtWidgets.QTextEdit(self)
        self.text.setPlaceholderText("Vui lòng nhập tệp địa chỉ IP")
        self.text.move(20, 50)
        self.btn_import = QtWidgets.QPushButton("nhập", self)
        self.btn_import.clicked.connect(self.import_file)
        self.btn_import.move(300, 50)
        # Tạo nút lưu kết quả
        self.save_button = QPushButton('Lưu kết quả', self)
        self.save_button.move(300, 150)
        self.save_button.clicked.connect(self.save_results)
        # Nút tạo
        self.ftp_button = QPushButton('ftp', self)
        self.ftp_button.move(500, 50)
        self.ftp_button.clicked.connect(lambda: self.test_all_ips(self.check_ftp))

        self.vnc_button = QPushButton('vnc', self)
        self.vnc_button.move(500, 100)
        self.vnc_button.clicked.connect(lambda: self.test_all_ips(self.check_vnc))

        self.solr_button = QPushButton('solr', self)
        self.solr_button.move(500, 150)
        self.solr_button.clicked.connect(lambda: self.test_all_ips(self.check_solr))

        self.weblogic_button = QPushButton('weblogic', self)
        self.weblogic_button.move(500, 200)
        self.weblogic_button.clicked.connect(lambda: self.test_all_ips(self.check_weblogic))

        self.jboss_button = QPushButton('JBoss', self)
        self.jboss_button.move(500, 250)
        self.jboss_button.clicked.connect(lambda: self.test_all_ips(self.check_jboss))

        self.es_button = QPushButton('elasticsearch', self)
        self.es_button.move(500, 300)
        self.es_button.clicked.connect(lambda: self.test_all_ips(self.check_elasticsearch))

        self.kubernetes_button = QPushButton('kubernetes', self)
        self.kubernetes_button.move(500, 350)
        self.kubernetes_button.clicked.connect(lambda: self.test_all_ips(self.check_kubernetes_api_server))

        self.dockerreg_button = QPushButton('docker registry', self)
        self.dockerreg_button.move(500, 400)
        self.dockerreg_button.clicked.connect(lambda: self.test_all_ips(self.check_docker_registry))

        self.ldap_button = QPushButton('LDAP', self)
        self.ldap_button.move(500, 450)
        self.ldap_button.clicked.connect(lambda: self.test_all_ips(self.check_ldap))

        self.jenkins_button = QPushButton('jenkins', self)
        self.jenkins_button.move(500, 500)
        self.jenkins_button.clicked.connect(lambda: self.test_all_ips(self.check_jenkins))


        self.redis_button = QPushButton('Redis', self)
        self.redis_button.move(600, 50)
        self.redis_button.clicked.connect(lambda: self.test_all_ips(self.check_redis))

        self.kibana_button = QPushButton('kibana', self)
        self.kibana_button.move(600, 100)
        self.kibana_button.clicked.connect(lambda: self.test_all_ips(self.check_kibana))

        self.spat_button = QPushButton('spring actuator', self)
        self.spat_button.move(600, 150)
        self.spat_button.clicked.connect(lambda: self.test_all_ips(self.check_spring_boot_actuator))

        self.wordpress_button = QPushButton('wordpress', self)
        self.wordpress_button.move(600, 200)
        self.wordpress_button.clicked.connect(lambda: self.test_all_ips(self.check_wordpress))

        self.nfs_button = QPushButton('Nfs', self)
        self.nfs_button.move(600, 250)
        self.nfs_button.clicked.connect(lambda: self.test_all_ips(self.check_nfs))

        self.ipc_button = QPushButton('ipc', self)
        self.ipc_button.move(600, 300)
        self.ipc_button.clicked.connect(lambda: self.test_all_ips(self.check_ipc))

        self.uwsgi_button = QPushButton('uwsgi', self)
        self.uwsgi_button.move(600, 350)
        self.uwsgi_button.clicked.connect(lambda: self.test_all_ips(self.check_uwsgi))

        self.harbor_button = QPushButton('harbor', self)
        self.harbor_button.move(600, 400)
        self.harbor_button.clicked.connect(lambda: self.test_all_ips(self.check_harbor))

        self.zookeeper_button = QPushButton('zookeeper', self)
        self.zookeeper_button.move(600, 450)
        self.zookeeper_button.clicked.connect(lambda: self.test_all_ips(self.check_zookeeper))

        self.druid_button = QPushButton('druid', self)
        self.druid_button.move(600, 500)
        self.druid_button.clicked.connect(lambda: self.test_all_ips(self.check_druid))

        self.swaggerui_button = QPushButton('swaggerui', self)
        self.swaggerui_button.move(700, 50)
        self.swaggerui_button.clicked.connect(lambda: self.test_all_ips(self.check_swaggerui))

        self.rabbitmq_button = QPushButton('rabbitmq', self)
        self.rabbitmq_button.move(700, 100)
        self.rabbitmq_button.clicked.connect(lambda: self.test_all_ips(self.check_rabbitmq))

        self.phpfpm_button = QPushButton('php_fpm_fastcgi', self)
        self.phpfpm_button.move(700, 150)
        self.phpfpm_button.clicked.connect(lambda: self.test_all_ips(self.check_php_fpm_fastcgi))

        self.atlc_button = QPushButton('atlassianc', self)
        self.atlc_button.move(700, 200)
        self.atlc_button.clicked.connect(lambda: self.test_all_ips(self.check_atlassian_crowd))

        self.docker_button = QPushButton('docker', self)
        self.docker_button.move(700, 250)
        self.docker_button.clicked.connect(lambda: self.test_all_ips(self.check_docker))

        self.dubbo_button = QPushButton('dubbo', self)
        self.dubbo_button.move(700, 300)
        self.dubbo_button.clicked.connect(lambda: self.test_all_ips(self.check_dubbo))

        self.mongodb_button = QPushButton('mongodb', self)
        self.mongodb_button.move(700, 350)
        self.mongodb_button.clicked.connect(lambda: self.test_all_ips(self.check_mongodb))

        self.zabbix_button = QPushButton('zabbix', self)
        self.zabbix_button.move(700, 400)
        self.zabbix_button.clicked.connect(lambda: self.test_all_ips(self.check_zabbix))

        self.memcached_button = QPushButton('memcached', self)
        self.memcached_button.move(700, 450)
        self.memcached_button.clicked.connect(lambda: self.test_all_ips(self.check_memcached))

        self.btphp_button = QPushButton('bt_phpmyadmin', self)
        self.btphp_button.move(700, 500)
        self.btphp_button.clicked.connect(lambda: self.test_all_ips(self.check_bt_phpmyadmin))

        self.rsync_button = QPushButton('rsync', self)
        self.rsync_button.move(800, 50)
        self.rsync_button.clicked.connect(lambda: self.test_all_ips(self.check_rsync))

        self.apsk_button = QPushButton('apache_spark', self)
        self.apsk_button.move(800, 100)
        self.apsk_button.clicked.connect(lambda: self.test_all_ips(self.check_apache_spark))

        self.kong_button = QPushButton('kong', self)
        self.kong_button.move(800, 150)
        self.kong_button.clicked.connect(lambda: self.test_all_ips(self.check_kong))

        self.couchdb_button = QPushButton('couchdb', self)
        self.couchdb_button.move(800, 200)
        self.couchdb_button.clicked.connect(lambda: self.test_all_ips(self.check_couchdb))

        self.hadoopyarn_button = QPushButton('hadoopYARN', self)
        self.hadoopyarn_button.move(800, 250)
        self.hadoopyarn_button.clicked.connect(lambda: self.test_all_ips(self.check_hadoop_yarn))

        self.jupyter_button = QPushButton('jupyter', self)
        self.jupyter_button.move(800, 300)
        self.jupyter_button.clicked.connect(lambda: self.test_all_ips(self.check_jupyter_notebook))

        self.tkad6_button = QPushButton('thinkadmin_v6', self)
        self.tkad6_button.move(800, 350)
        self.tkad6_button.clicked.connect(lambda: self.test_all_ips(self.check_thinkadmin_v6))

        self.activemq_button = QPushButton('activemq', self)
        self.activemq_button.move(800, 400)
        self.activemq_button.clicked.connect(lambda: self.test_all_ips(self.check_activemq))

        self.result_label = QtWidgets.QPlainTextEdit(self)
        self.result_label.setReadOnly(True)
        self.result_label.setPlaceholderText("Kết quả kiểm tra sẽ được hiển thị ở đây.")
        self.result_label.setGeometry(20, 350, 460, 200)

        self.setGeometry(600, 600, 1000, 600)
        self.show()

    # Nhập tệp địa chỉ IP và hiển thị nó trong hộp văn bản
    def import_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Chọn tập tin", "", "Text Files (*.txt)")

        if file_name:
            try:
                with open(file_name, "r") as f:
                    ip_list = f.read().splitlines()
                self.text.setPlainText("\n".join(ip_list))
            except Exception as e:
                QtWidgets.QMessageBox.warning(self, "cảnh báo", str(e))

    # Kiểm tra tất cả các địa chỉ IP và hiển thị kết quả trong tab kết quả
    def test_all_ips(self, check_fn):
        ip_list = self.text.toPlainText().splitlines()
        if not ip_list:
            QtWidgets.QMessageBox.warning(self, "Cảnh báo", "Vui lòng nhập tệp địa chỉ IP hoặc nhập địa chỉ IP")
            return

        results = []
        for ip in ip_list:
            results.append(check_fn(ip))

        self.result_label.setPlainText("\n".join(results))
        # Lưu kết quả vào tập tin txt

    def save_results(self):
        file_name, _ = QFileDialog.getSaveFileName(self, "lưu tập tin", "", "Text Files (*.txt)")

        if file_name:
            with open(file_name, "w") as f:
                f.write(self.result_label.toPlainText())
    # Kiểm tra FTP để tìm lỗ hổng truy cập trái phép
    def check_ftp(self, ip):
        try:
            ftp = ftplib.FTP(ip)
            ftp.login()
            ftp.cwd('/')
            ftp.quit()
            result = f"{ip}[+]Lỗ hổng truy cập trái phép FTP tồn tại"
        except:
            result = f"{ip} Ftp không thể kết nối"

        return result

    def check_jboss(self, ip):

        # Kiểm tra JBoss để phát hiện các lỗ hổng truy cập trái phép
        jboss_url = f'http://{ip}:8080/jmx-console/'
        try:
            jboss_response = requests.get(jboss_url,timeout=5)
            if 'jboss' in jboss_response.headers.get('Server', '') and 'Welcome to JBossAS' in jboss_response.text:
                result = f"{ip}[+]Có lỗ hổng truy cập trái phép trong jboss"
            else:
                result = f"{ip}Không có lỗ hổng truy cập trái phép jboss"
        except:
            result = f"{ip}Jboss không thể kết nối"
        # Hiển thị kết quả
        return result

        # Kiểm tra Solr để tìm lỗ hổng truy cập trái phép

    def check_solr(self, ip):

        solr_url = f'http://{ip}:8983/solr/'
        try:
            response = requests.get(solr_url, timeout=5)
            if 'Apache Solr' in response.text:
                result = f"{ip}[+]Tồn tại solr Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại solr Lỗ hổng truy cập trái phép"

        except:
            result = f"{ip}solr Không thể kết nối"
            # Hiển thị kết quả
        return result

        # Kiểm tra WebLogic để tìm lỗ hổng truy cập trái phép

    def check_weblogic(self, ip):

        weblogic_url = f'http://{ip}:7001/console/login/LoginForm.jsp'

        try:
            response = requests.get(weblogic_url, timeout=5)
            if 'Oracle WebLogic Server' in response.text:
                result = f"{ip}[+]Tồn tại Lỗ hổng truy cập trái phép Weblogic"
            else:
                result = f"{ip}Không tồn tại weblogic Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}weblogic Không thể kết nối"

        # Hiển thị kết quả
        return result



    def check_ldap(self, ip):

        # Kiểm tra LDAP để tìm lỗ hổng truy cập trái phép
        ldap_url = ip + ':389'
        try:
            ldap_response = requests.get(ldap_url)
            if 'OpenLDAP' in ldap_response.headers.get('Server', '') and '80090308' in ldap_response.text:
                result = f"{ip}[+]Tồn tại ldap Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại ldap Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}ldap Không thể kết nối"

        # Hiển thị kết quả
        return result

    def check_redis(self, ip):

        # Kiểm tra Redis để tìm lỗ hổng truy cập trái phép
        redis_url = ip + ':6379/info'
        try:
            redis_response = requests.get(redis_url, allow_redirects=False)
            if redis_response.status_code == 200 and 'redis_version' in redis_response.text:
                result = f"{ip}[+]Tồn tại redis Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại redis Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}redis Không thể kết nối"

        # Hiển thị kết quả
        return result

    def check_nfs(self, ip):

        # Kiểm tra NFS để tìm lỗ hổng truy cập trái phép
        try:
            nfs_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            nfs_socket.settimeout(3)
            nfs_socket.connect((ip, 2049))
            nfs_socket.sendall(
                b'\x80\x00\x00\x28\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x20\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
            response = nfs_socket.recv(1024)
            if b'\x80\x00\x00\x28\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x20\x00\x00\x02\x00\x00\x00\x01' in response:
                result = f"{ip}[+]Tồn tại nfs Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại nfs Lỗ hổng truy cập trái phép"
        except:
            result = f"nfs Không thể kết nối đến {ip}"

        # Hiển thị kết quả
        return result

    def check_zookeeper(self, ip):

        # Kiểm tra Zookeeper để tìm lỗ hổng truy cập trái phép
        zookeeper_url = ip + ':2181'
        try:
            zookeeper_response = requests.get(zookeeper_url, timeout=5)
            if 'Zookeeper' in zookeeper_response.headers.get('Server',
                                                             '') and zookeeper_response.status_code == 200:
                result = f"{ip}[+]Tồn tại zookeeper Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại zookeeper Lỗ hổng truy cập trái phép"
        except:
            result = " Không thể kết nối đến Zookeeper "
        # Hiển thị kết quả
        return result

    # Kiểm tra VNC để tìm lỗ hổng truy cập trái phép
    def check_vnc(self, ip):

        vnc_url = f'vnc://{ip}'
        try:
            tigerVNC_response = requests.get(vnc_url, timeout=5)
            if "RFB 003.008\n" in tigerVNC_response.content.decode('utf-8'):
                result = f"{ip}[+]Tồn tại vnc Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại vnc Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}vnc Không thể kết nối"

        # Hiển thị kết quả
        return result

    # Kiểm tra Elasticsearch để tìm lỗ hổng truy cập trái phép
    def check_elasticsearch(self, ip):

        url = f'http://{ip}:8000/_cat'
        try:
            response = requests.get(url, timeout=5)
            if '/_cat/master' in response.text:
                result = f"{ip}[+]Tồn tại elasticsearch Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại elasticsearch Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}es Không thể kết nối"

        # Hiển thị kết quả
        return result

    # Kiểm tra Jenkins để tìm lỗ hổng truy cập trái phép
    def check_jenkins(self, ip):

        jenkins_url = f'http://{ip}:8080'
        try:
            response = requests.get(jenkins_url, timeout=5)
            if 'jenkins' in response.headers.get('X-Jenkins', '') and 'Dashboard [Jenkins]' in response.text:
                result = f"{ip}[+]Tồn tại jenkins Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại jenkins Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}jenkins Không thể kết nối"

        # Hiển thị kết quả
        return result

    # Kiểm tra Kibana để tìm lỗ hổng truy cập trái phép
    def check_kibana(self, ip):

        kibana_url = f'http://{ip}:5601'
        try:
            response = requests.get(kibana_url, timeout=5)
            if 'kbn-name="kibana"' in response.text:
                result = f"{ip}[+]Tồn tại kibana Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại kibana Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}kibana Không thể kết nối"

        # Hiển thị kết quả
        return result

    # Kiểm tra IPC để tìm lỗ hổng truy cập trái phép
    def check_ipc(self, ip):

        ipc_url = f'http://{ip}:445'
        try:
            response = requests.get(ipc_url, timeout=5)
            if 'IPC Service' in response.text:
                result = f"{ip}[+]Tồn tại ipc Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại ipc Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}ipc Không thể kết nối"

        # Hiển thị kết quả
        return result

    # Kiểm tra Druid để tìm lỗ hổng truy cập trái phép
    def check_druid(self, ip):

        druid_url = f'http://{ip}:8888/druid/index.html'
        try:
            response = requests.get(druid_url, timeout=5)
            if 'Druid Console' in response.text:
                result = f"{ip}[+]Tồn tại druid Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại druid Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}druid Không thể kết nối"

            # Hiển thị kết quả
        return result

    def check_swaggerui(self, ip):

        # Kiểm tra SwaggerUI để tìm lỗ hổng truy cập trái phép
        swaggerui_url = ip + '/swagger-ui.html'
        try:
            swaggerui_response = requests.get(swaggerui_url, timeout=5)
            if 'Swagger' in swaggerui_response.text:
                result = f"{ip}[+]Tồn tại swaggerui Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại swaggerui Lỗ hổng truy cập trái phép"
        except:
            result = " Không thể kết nối đến SwaggerUI "
        # Hiển thị kết quả
        return result

    def check_docker(self, ip):

        # Kiểm tra Docker để tìm lỗ hổng truy cập trái phép
        docker_url = 'http://' + ip + ':2375/version'
        try:
            docker_response = requests.get(docker_url, timeout=5)
            if docker_response.status_code == 200 and 'ApiVersion' in docker_response.json():
                result = f"{ip}[+]Tồn tại docker Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại docker Lỗ hổng truy cập trái phép"
        except:
            result = " Không thể kết nối đến Docker "
        # Hiển thị kết quả
        return result

    # Kiểm tra RabbitMQ để tìm lỗ hổng truy cập trái phép
    def check_rabbitmq(self, ip):

        rabbitmq_url = f'http://{ip}:15672/'

        try:
            response = requests.get(rabbitmq_url, timeout=5)
            if 'RabbitMQ Management' in response.text and 'overview-module' in response.text:
                result = f"{ip}[+]Tồn tại rabbitmq Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại rabbitmq Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}rabbitmq Không thể kết nối"

        # Hiển thị kết quả
        return result

    # Kiểm tra Memcached để tìm lỗ hổng truy cập trái phép
    def check_memcached(self, ip):

        try:
            memcached_client = memcache.Client([ip], timeout=5)
            stats = memcached_client.get_stats()
            if len(stats) > 0:
                result = f"{ip}[+]Tồn tại memcached Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại memcached Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}memcached Không thể kết nối"

        # Hiển thị kết quả
        return result

    # Kiểm tra Dubbo để tìm lỗ hổng truy cập trái phép
    def check_dubbo(self, ip):

        url = f'http://{ip}:8080/'
        try:
            response = requests.get(url, timeout=5)
            if 'dubbo' in response.headers and 'Welcome to the Dubbo' in response.text:
                result = f"{ip}[+]Tồn tại dubbo Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại dubbo Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}dubbo Không thể kết nối"

        # Hiển thị kết quả
        return result

    # Kiểm tra宝塔phpmyadminđể tìm lỗ hổng truy cập trái phép
    def check_bt_phpmyadmin(self, ip):

        phpmyadmin_url = f'http://{ip}/phpmyadmin/'
        try:
            response = requests.get(phpmyadmin_url, timeout=5)
            if 'phpMyAdmin' in response.text:
                result = f"{ip}[+]Tồn tại bt_phpmyadmin Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại bt_phpmyadmin Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}btphpmydamin Không thể kết nối"

        # Hiển thị kết quả
        return result

    # Kiểm tra Rsync để tìm lỗ hổng truy cập trái phép
    def check_rsync(self, ip):

        rsync_url = f'rsync://{ip}'
        try:
            response = requests.get(rsync_url, timeout=5)
            if 'rsync' in response.headers.get('Server', '') and 'rsyncd.conf' in response.text:
                result = f"{ip}[+]Tồn tại rsync Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại rsync Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}rsync Không thể kết nối"

        # Hiển thị kết quả
        return result

    # Kiểm tra Kubernetes Api Server để tìm lỗ hổng truy cập trái phép
    def check_kubernetes_api_server(self, ip):

        api_server_url = f'https://{ip}:6443/api/'

        try:
            response = requests.get(api_server_url, verify=False, timeout=5)
            if 'Unauthorized' in response.text:
                result = f"{ip}[+]Tồn tại kubernetes_api_server Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại kubernetes_api_server Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}kubernetes Không thể kết nối"

        # Hiển thị kết quả
        return result

    # Kiểm tra CouchDB để tìm lỗ hổng truy cập trái phép
    def check_couchdb(self, ip):

        couchdb_url = f'http://{ip}:5984/_utils/'

        try:
            response = requests.get(couchdb_url, timeout=5)
            if 'Welcome to CouchDB' in response.text:
                result = f"{ip}[+]Tồn tại couchdb Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại couchdb Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}couchdb Không thể kết nối"

        # Hiển thị kết quả
        return result

    # Kiểm tra Spring Boot Actuator để tìm lỗ hổng truy cập trái phép
    def check_spring_boot_actuator(self, ip):

        actuator_url = f'http://{ip}:8080/actuator/'

        try:
            response = requests.get(actuator_url, timeout=5)
            if 'Hystrix' in response.text and 'health" : {' in response.text:
                result = f"{ip}[+]Tồn tại spring_boot_actuator Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại spring_boot_actuator Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}actuator Không thể kết nối"

        # Hiển thị kết quả
        return result

    # Kiểm tra uWSGI để tìm lỗ hổng truy cập trái phép
    def check_uwsgi(self, ip):

        uwsgi_url = f'http://{ip}:1717/'

        try:
            response = requests.get(uwsgi_url, timeout=5)
            if 'uWSGI Status' in response.text:
                result = f"{ip}[+]Tồn tại uwsgi Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại uwsgi Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}uwsgi Không thể kết nối"

        # Hiển thị kết quả
        return result

    # Kiểm tra ThinkAdmin V6 để tìm lỗ hổng truy cập trái phép
    def check_thinkadmin_v6(self, ip):

        thinkadmin_url = f'http://{ip}/index/login.html'

        try:
            response = requests.get(thinkadmin_url, timeout=5)
            if 'ThinkAdmin' in response.text and 'logincheck' in response.text:
                result = f"{ip}[+]Tồn tại thinkadmin_v6 Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại thinkadmin_v6 Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}thinkadminv6 Không thể kết nối"

        # Hiển thị kết quả
        return result

    # Kiểm tra PHP-FPM Fastcgi để tìm lỗ hổng truy cập trái phép
    def check_php_fpm_fastcgi(self, ip):

        php_fpm_url = f'http://{ip}/php-fpm_status'

        try:
            response = requests.get(php_fpm_url, timeout=5)
            if 'pool:' in response.text and 'processes' in response.text:
                result = f"{ip}[+]Tồn tại php_fpm_fastcgi Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại php_fpm_fastcgi Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}phpfpm Không thể kết nối"

        # Hiển thị kết quả
        return result

    # Kiểm tra MongoDB để tìm lỗ hổng truy cập trái phép
    def check_mongodb(self, ip):

        mongodb_url = f'mongodb://{ip}:27017/'

        try:
            client = pymongo.MongoClient(mongodb_url, serverSelectionTimeoutMS=5000)
            dbs = client.list_database_names()
            if len(dbs) > 0:
                result = f"{ip}[+]Tồn tại mongodb Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại mongodb Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}mongodb Không thể kết nối"

        # Hiển thị kết quả
        return result

    # Kiểm tra Jupyter Notebook để tìm lỗ hổng truy cập trái phép
    def check_jupyter_notebook(self, ip):

        notebook_url = f'http://{ip}:8888/'

        try:
            response = requests.get(notebook_url, timeout=5)
            if 'Jupyter Notebook' in response.text:
                result = f"{ip}[+]Tồn tại jupyter_notebook Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại jupyter_notebook Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}jupyter Không thể kết nối"

        # Hiển thị kết quả
        return result

    # Kiểm tra Apache Spark để tìm lỗ hổng truy cập trái phép
    def check_apache_spark(self, ip):

        spark_url = f'http://{ip}:8080/'

        try:
            response = requests.get(spark_url, timeout=5)
            if 'Spark Master at' in response.text and 'Workers' in response.text:
                result = f"{ip}[+]Tồn tại apache_spark Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại apache_spark Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}spark Không thể kết nối"

        # Hiển thị kết quả
        return result

    # Kiểm tra Docker Registry để tìm lỗ hổng truy cập trái phép
    def check_docker_registry(self, ip):

        registry_url = f'http://{ip}/v2/_catalog'

        try:
            response = requests.get(registry_url, timeout=5)
            if 'repositories' in response.json():
                result = f"{ip}[+]Tồn tại docker_registry Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại docker_registry Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}registry Không thể kết nối"

        # Hiển thị kết quả
        return result

    # Kiểm tra Hadoop YARN để tìm lỗ hổng truy cập trái phép
    def check_hadoop_yarn(self, ip):

        yarn_url = f'http://{ip}:8088/ws/v1/cluster/info'

        try:
            response = requests.get(yarn_url, timeout=5)
            if 'resourceManagerVersion' in response.json()['clusterInfo']:
                result = f"{ip}[+]Tồn tại hadoop_yarn Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại hadoop_yarn Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}yarn Không thể kết nối"

        # Hiển thị kết quả
        return result

    # Kiểm tra Kong để tìm lỗ hổng truy cập trái phép
    def check_kong(self, ip):

        kong_url = f'http://{ip}:8001/'

        try:
            response = requests.get(kong_url, timeout=5)
            if 'Welcome to Kong' in response.text:
                result = f"{ip}[+]Tồn tại kong Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại kong Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}kong Không thể kết nối"

        # Hiển thị kết quả
        return result

    # Kiểm tra WordPress để tìm lỗ hổng truy cập trái phép
    def check_wordpress(self, ip):

        wordpress_url = f'http://{ip}/wp-login.php'

        try:
            response = requests.get(wordpress_url, timeout=5)
            if 'WordPress' in response.text:
                result = f"{ip}[+]Tồn tại wordpress Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại wordpress Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}wordpress Không thể kết nối"

        # Hiển thị kết quả
        return result

    # Kiểm tra Zabbix để tìm lỗ hổng truy cập trái phép
    def check_zabbix(self, ip):

        zabbix_url = f'http://{ip}/zabbix/jsrpc.php'

        try:
            headers = {
                'Content-Type': 'application/json-rpc',
                'User-Agent': 'Mozilla/5.0'
            }
            data = '{"jsonrpc":"2.0","method":"user.login","params":{"user":"","password":""},"id":0}'
            response = requests.post(zabbix_url, headers=headers, data=data, timeout=5)
            if 'result' in response.json():
                result = f"{ip}[+]Tồn tại zabbix Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại zabbix Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}zabbix Không thể kết nối"

        # Hiển thị kết quả
        return result

    # Kiểm tra Active MQ để tìm lỗ hổng truy cập trái phép
    def check_activemq(self, ip):

        activemq_url = f'http://{ip}:8161/admin/'

        try:
            response = requests.get(activemq_url, timeout=5)
            if 'Apache ActiveMQ' in response.text:
                result = f"{ip}[+]Tồn tại activemq Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại activemq Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}activemq Không thể kết nối"

        # Hiển thị kết quả
        return result

    # Kiểm tra Harbor để tìm lỗ hổng truy cập trái phép
    def check_harbor(self, ip):

        harbor_url = f'http://{ip}/api/v2.0/statistics'

        try:
            response = requests.get(harbor_url, timeout=5)
            if 'total_projects' in response.json():
                result = f"{ip}[+]Tồn tại harbor Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại harbor Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}harbor Không thể kết nối"

        # Hiển thị kết quả
        return result

    # Kiểm tra Atlassian Crowd để tìm lỗ hổng truy cập trái phép
    def check_atlassian_crowd(self, ip):

        crowd_url = f'http://{ip}:8095/crowd/'

        try:
            response = requests.get(crowd_url, timeout=5)
            if 'Atlassian Crowd' in response.text:
                result = f"{ip}[+]Tồn tại atlassian_crowd Lỗ hổng truy cập trái phép"
            else:
                result = f"{ip}Không tồn tại atlassian_crowd Lỗ hổng truy cập trái phép"
        except:
            result = f"{ip}atlassian Không thể kết nối"

        # Hiển thị kết quả
        return result
if __name__ == '__main__':
    app = QApplication(sys.argv)
    security_checker = SecurityChecker()
    sys.exit(app.exec_())

from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import hashlib

Base = declarative_base()

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    vuln_id = Column(String(64), unique=True, index=True)  # 漏洞唯一标识
    vuln_name = Column(String(200))  # 漏洞名称
    severity = Column(String(20))  # 危险等级
    details = Column(Text)  # 漏洞详情
    first_discovery_time = Column(DateTime)  # 首次发现时间
    test_time = Column(DateTime)  # 测试时间
    current_status = Column(String(20))  # 当前状态
    asset_info = Column(JSON)  # 资产信息JSON
    source = Column(String(50))  # 漏洞来源
    remarks = Column(Text)  # 备注

    # 关联历史记录
    history = relationship("VulnerabilityHistory", back_populates="vulnerability")

    @staticmethod
    def generate_vuln_id(vuln_name, asset_ip, asset_port, target_url, system, customer):
        """生成漏洞唯一标识"""
        content = f"{vuln_name}{asset_ip}{asset_port}{target_url}{system}{customer}"
        return hashlib.sha256(content.encode()).hexdigest()

class VulnerabilityHistory(Base):
    __tablename__ = "vulnerability_history"

    id = Column(Integer, primary_key=True, index=True)
    vuln_id = Column(String(64), ForeignKey("vulnerabilities.vuln_id"))
    discovery_time = Column(DateTime, default=datetime.now)  # 发现时间
    status = Column(String(20))  # 当时状态
    source = Column(String(50))  # 发现来源
    remarks = Column(Text)  # 备注

    # 关联漏洞
    vulnerability = relationship("Vulnerability", back_populates="history") 
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from typing import List, Dict
import pandas as pd
from datetime import datetime
import models
import database
from pydantic import BaseModel
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
import os
import json
from sqlalchemy import func, desc, asc, text, cast, String
from sqlalchemy.dialects.postgresql import JSONB

app = FastAPI()

# 添加CORS中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 在生产环境中应该设置具体的域名
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 创建数据库表
models.Base.metadata.create_all(bind=database.engine)

class AssetInfo(BaseModel):
    ip: str
    port: str
    url: str
    system: str
    customer: str
    owner: str

class VulnerabilityBase(BaseModel):
    id: int = None
    vuln_id: str
    vuln_name: str
    severity: str
    details: str
    first_discovery_time: datetime
    test_time: datetime
    current_status: str
    asset_info: AssetInfo
    source: str
    remarks: str = None

    class Config:
        from_attributes = True

class VulnerabilityHistoryBase(BaseModel):
    id: int = None
    vuln_id: str
    discovery_time: datetime
    status: str
    source: str
    remarks: str = None

    class Config:
        from_attributes = True

class ChartData(BaseModel):
    severity_distribution: Dict[str, int]
    monthly_trend: Dict[str, int]
    monthly_discovery_fix: Dict[str, Dict[str, int]]
    status_distribution: Dict[str, int]

@app.get("/vulnerabilities/{vuln_id}/history", response_model=List[VulnerabilityHistoryBase])
def get_vulnerability_history(vuln_id: str, db: Session = Depends(database.get_db)):
    history = db.query(models.VulnerabilityHistory).filter(
        models.VulnerabilityHistory.vuln_id == vuln_id
    ).order_by(models.VulnerabilityHistory.discovery_time.desc()).all()
    return history

@app.get("/vulnerabilities/", response_model=List[VulnerabilityBase])
def read_vulnerabilities(
    skip: int = 0,
    limit: int = 100,
    source: str = None,
    customer: str = None,
    system: str = None,
    owner: str = None,
    asset_ip: str = None,
    asset_port: str = None,
    target_url: str = None,
    vuln_name: str = None,
    severity: str = None,
    status: str = None,
    start_time: str = None,
    end_time: str = None,
    db: Session = Depends(database.get_db)
):
    query = db.query(models.Vulnerability)
    
    # 应用筛选条件
    if source:
        query = query.filter(models.Vulnerability.source == source)
    if customer:
        query = query.filter(func.json_extract(models.Vulnerability.asset_info, '$.customer').like(f'%{customer}%'))
    if system:
        query = query.filter(func.json_extract(models.Vulnerability.asset_info, '$.system').like(f'%{system}%'))
    if owner:
        query = query.filter(func.json_extract(models.Vulnerability.asset_info, '$.owner').like(f'%{owner}%'))
    if asset_ip:
        query = query.filter(func.json_extract(models.Vulnerability.asset_info, '$.ip').like(f'%{asset_ip}%'))
    if asset_port:
        query = query.filter(func.json_extract(models.Vulnerability.asset_info, '$.port') == asset_port)
    if target_url:
        query = query.filter(func.json_extract(models.Vulnerability.asset_info, '$.url').like(f'%{target_url}%'))
    if vuln_name:
        query = query.filter(models.Vulnerability.vuln_name.like(f'%{vuln_name}%'))
    if severity:
        query = query.filter(models.Vulnerability.severity == severity)
    if status:
        query = query.filter(models.Vulnerability.current_status == status)
    if start_time:
        query = query.filter(models.Vulnerability.first_discovery_time >= start_time)
    if end_time:
        query = query.filter(models.Vulnerability.first_discovery_time <= end_time)
    
    vulnerabilities = query.offset(skip).limit(limit).all()
    return vulnerabilities

@app.post("/upload/")
async def upload_file(file: UploadFile = File(...), db: Session = Depends(database.get_db)):
    if not file.filename.endswith('.xlsx'):
        raise HTTPException(status_code=400, detail="只支持Excel文件")
    
    try:
        contents = await file.read()
        temp_file = "temp_upload.xlsx"
        with open(temp_file, "wb") as f:
            f.write(contents)
        
        df = pd.read_excel(temp_file)
        
        required_columns = ['source', 'customer', 'system', 'owner', 'asset_ip', 
                          'asset_port', 'target_url', 'vuln_name', 'severity', 
                          'details', 'test_time', 'status']
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            os.remove(temp_file)
            raise HTTPException(status_code=400, detail=f"Excel文件缺少必要的列: {', '.join(missing_columns)}")
        
        for _, row in df.iterrows():
            try:
                # 生成漏洞ID
                vuln_id = models.Vulnerability.generate_vuln_id(
                    str(row['vuln_name']),
                    str(row['asset_ip']),
                    str(row['asset_port']),
                    str(row['target_url']),
                    str(row['system']),
                    str(row['customer'])
                )

                # 准备资产信息
                asset_info = {
                    'ip': str(row['asset_ip']),
                    'port': str(row['asset_port']),
                    'url': str(row['target_url']),
                    'system': str(row['system']),
                    'customer': str(row['customer']),
                    'owner': str(row['owner'])
                }

                # 处理日期
                try:
                    # 尝试解析ISO格式时间字符串
                    test_time_str = str(row['test_time'])
                    if 'T' in test_time_str:
                        test_time = datetime.fromisoformat(test_time_str.replace('Z', '+00:00'))
                    else:
                        test_time = pd.to_datetime(row['test_time'])
                except Exception as e:
                    print(f"日期解析错误: {str(e)}, 使用当前时间")
                    test_time = datetime.now()

                status = str(row.get('status', '存在'))

                # 检查是否存在相同漏洞
                existing_vuln = db.query(models.Vulnerability).filter(
                    models.Vulnerability.vuln_id == vuln_id
                ).first()

                if existing_vuln:
                    # 更新现有漏洞
                    existing_vuln.test_time = test_time
                    existing_vuln.current_status = status
                    
                    # 添加历史记录
                    history = models.VulnerabilityHistory(
                        vuln_id=vuln_id,
                        discovery_time=test_time,
                        status=status,
                        source=str(row['source']),
                        remarks=str(row.get('remarks', ''))
                    )
                    db.add(history)
                else:
                    # 创建新漏洞
                    vulnerability = models.Vulnerability(
                        vuln_id=vuln_id,
                        vuln_name=str(row['vuln_name']),
                        severity=str(row['severity']),
                        details=str(row['details']),
                        first_discovery_time=test_time,
                        test_time=test_time,
                        current_status=status,
                        asset_info=asset_info,
                        source=str(row['source']),
                        remarks=str(row.get('remarks', ''))
                    )
                    db.add(vulnerability)
                    
                    # 添加历史记录
                    history = models.VulnerabilityHistory(
                        vuln_id=vuln_id,
                        discovery_time=test_time,
                        status=status,
                        source=str(row['source']),
                        remarks=str(row.get('remarks', ''))
                    )
                    db.add(history)

            except Exception as e:
                print(f"处理行数据时出错: {str(e)}")
                continue
        
        db.commit()
        os.remove(temp_file)
        return {"message": "文件上传成功", "status": "success"}
    except Exception as e:
        if os.path.exists(temp_file):
            os.remove(temp_file)
        db.rollback()
        raise HTTPException(status_code=500, detail=f"处理文件时出错: {str(e)}")

@app.get("/download/template")
async def download_template():
    data = {
        'source': ['扫描器/手动测试'],
        'customer': ['客户名称'],
        'system': ['系统名称'],
        'owner': ['负责人'],
        'asset_ip': ['192.168.1.1'],
        'asset_port': ['80'],
        'target_url': ['http://example.com'],
        'vuln_name': ['漏洞名称'],
        'severity': ['高危/中危/低危'],
        'details': ['漏洞详情描述'],
        'test_time': [datetime.now()],
        'status': ['存在/不存在'],
        'remarks': ['备注信息']
    }
    
    df = pd.DataFrame(data)
    template_path = "vulnerability_template.xlsx"
    df.to_excel(template_path, index=False)
    
    return FileResponse(
        template_path,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        filename="vulnerability_template.xlsx"
    )

@app.get("/vulnerabilities/count/")
def count_vulnerabilities(
    source: str = None,
    customer: str = None,
    system: str = None,
    owner: str = None,
    asset_ip: str = None,
    asset_port: str = None,
    target_url: str = None,
    vuln_name: str = None,
    severity: str = None,
    status: str = None,
    start_time: str = None,
    end_time: str = None,
    db: Session = Depends(database.get_db)
):
    query = db.query(models.Vulnerability)
    
    # 应用筛选条件
    if source:
        query = query.filter(models.Vulnerability.source == source)
    if customer:
        query = query.filter(func.json_extract(models.Vulnerability.asset_info, '$.customer').like(f'%{customer}%'))
    if system:
        query = query.filter(func.json_extract(models.Vulnerability.asset_info, '$.system').like(f'%{system}%'))
    if owner:
        query = query.filter(func.json_extract(models.Vulnerability.asset_info, '$.owner').like(f'%{owner}%'))
    if asset_ip:
        query = query.filter(func.json_extract(models.Vulnerability.asset_info, '$.ip').like(f'%{asset_ip}%'))
    if asset_port:
        query = query.filter(func.json_extract(models.Vulnerability.asset_info, '$.port') == asset_port)
    if target_url:
        query = query.filter(func.json_extract(models.Vulnerability.asset_info, '$.url').like(f'%{target_url}%'))
    if vuln_name:
        query = query.filter(models.Vulnerability.vuln_name.like(f'%{vuln_name}%'))
    if severity:
        query = query.filter(models.Vulnerability.severity == severity)
    if status:
        query = query.filter(models.Vulnerability.current_status == status)
    if start_time:
        query = query.filter(models.Vulnerability.first_discovery_time >= start_time)
    if end_time:
        query = query.filter(models.Vulnerability.first_discovery_time <= end_time)
    
    total = query.count()
    return {"total": total}

@app.get("/vulnerabilities/charts/", response_model=ChartData)
def get_chart_data(
    source: str = None,
    customer: str = None,
    system: str = None,
    owner: str = None,
    asset_ip: str = None,
    asset_port: str = None,
    target_url: str = None,
    vuln_name: str = None,
    severity: str = None,
    status: str = None,
    start_time: str = None,
    end_time: str = None,
    db: Session = Depends(database.get_db)
):
    # 构建筛选条件
    filter_conditions = []
    params = {}
    
    if source:
        filter_conditions.append("v.source = :source")
        params['source'] = source
    if customer:
        filter_conditions.append("json_extract(v.asset_info, '$.customer') = :customer")
        params['customer'] = customer
    if system:
        filter_conditions.append("json_extract(v.asset_info, '$.system') = :system")
        params['system'] = system
    if owner:
        filter_conditions.append("json_extract(v.asset_info, '$.owner') = :owner")
        params['owner'] = owner
    if asset_ip:
        filter_conditions.append("json_extract(v.asset_info, '$.ip') = :asset_ip")
        params['asset_ip'] = asset_ip
    if asset_port:
        filter_conditions.append("json_extract(v.asset_info, '$.port') = :asset_port")
        params['asset_port'] = asset_port
    if target_url:
        filter_conditions.append("json_extract(v.asset_info, '$.url') = :target_url")
        params['target_url'] = target_url
    if vuln_name:
        filter_conditions.append("v.vuln_name = :vuln_name")
        params['vuln_name'] = vuln_name
    if severity:
        filter_conditions.append("v.severity = :severity")
        params['severity'] = severity
    if status:
        filter_conditions.append("v.current_status = :status")
        params['status'] = status
    if start_time:
        filter_conditions.append("v.first_discovery_time >= :start_time")
        params['start_time'] = start_time
    if end_time:
        filter_conditions.append("v.first_discovery_time <= :end_time")
        params['end_time'] = end_time

    where_clause = " AND ".join(filter_conditions) if filter_conditions else "1=1"

    # 1. 获取漏洞等级分布（仅统计当前状态为"存在"的漏洞）
    severity_query = f"""
    SELECT v.severity, COUNT(*) as count
    FROM vulnerabilities v
    WHERE {where_clause} AND v.current_status = '存在'
    GROUP BY v.severity
    """
    severity_result = db.execute(text(severity_query), params)
    severity_distribution = {row[0]: row[1] for row in severity_result}

    # 2. 获取月度发现趋势（按首次发现时间统计）
    monthly_trend_query = f"""
    SELECT 
        strftime('%Y-%m', v.first_discovery_time) as month,
        COUNT(*) as count
    FROM vulnerabilities v
    WHERE {where_clause}
    GROUP BY strftime('%Y-%m', v.first_discovery_time)
    ORDER BY month
    """
    monthly_trend_result = db.execute(text(monthly_trend_query), params)
    monthly_trend = {row[0]: row[1] for row in monthly_trend_result}

    # 3. 获取每月发现/修复数量
    monthly_discovery_fix_query = f"""
    SELECT 
        strftime('%Y-%m', v.first_discovery_time) as month,
        COUNT(*) as discovery_count,
        SUM(CASE WHEN v.current_status = '不存在' THEN 1 ELSE 0 END) as fix_count
    FROM vulnerabilities v
    WHERE {where_clause}
    GROUP BY strftime('%Y-%m', v.first_discovery_time)
    ORDER BY month
    """
    monthly_discovery_fix_result = db.execute(text(monthly_discovery_fix_query), params)
    monthly_discovery_fix = {
        row[0]: {
            "discovery": row[1],
            "fix": row[2]
        } for row in monthly_discovery_fix_result
    }

    # 4. 获取修复/未修复漏洞占比
    status_distribution_query = f"""
    SELECT v.current_status, COUNT(*) as count
    FROM vulnerabilities v
    WHERE {where_clause}
    GROUP BY v.current_status
    """
    status_distribution_result = db.execute(text(status_distribution_query), params)
    status_distribution = {row[0]: row[1] for row in status_distribution_result}

    return ChartData(
        severity_distribution=severity_distribution,
        monthly_trend=monthly_trend,
        monthly_discovery_fix=monthly_discovery_fix,
        status_distribution=status_distribution
    ) 
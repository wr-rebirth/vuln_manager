# 漏洞管理系统

一个基于 Vue 3 和 FastAPI 的漏洞管理系统，用于管理和追踪安全漏洞。

## 功能特点

- 漏洞信息管理（增删改查）
- 数据导入导出（Excel格式）
- 多条件组合筛选
- 实时数据统计和可视化
- 漏洞历史记录追踪
- 支持模糊搜索和精确匹配

## 技术栈

### 前端
- Vue 3
- Element Plus UI框架
- ECharts 图表库
- Axios HTTP客户端

### 后端
- FastAPI
- SQLAlchemy ORM
- SQLite数据库
- Pandas (Excel文件处理)

## 环境要求

- Python 3.9+
- Node.js 16+
- npm 8+
- Docker 20.10+
- Docker Compose 2.0+

## 快速开始

### 1. 使用 Docker 部署（推荐）

#### 1.1 克隆项目

```bash
git clone [项目地址]
cd vuln_manager
```

#### 1.2 构建和启动容器
```bash
# 构建镜像并启动容器
docker-compose up -d

# 查看容器状态
docker-compose ps

# 查看日志
docker-compose logs -f
```

#### 1.3 访问服务
- 前端页面：http://localhost:8080
- 后端API：http://localhost:8000
- API文档：http://localhost:8000/docs

#### 1.4 停止服务
```bash
# 停止容器
docker-compose down

# 停止容器并删除数据卷
docker-compose down -v
```

### 2. 手动部署

#### 2.1 后端部署

##### 2.1.1 创建虚拟环境
```bash
# 创建虚拟环境
python -m venv venv

# 激活虚拟环境
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate
```

##### 2.1.2 安装依赖
```bash
# 安装后端依赖
pip install fastapi
pip install uvicorn
pip install sqlalchemy
pip install pandas
pip install openpyxl
pip install python-multipart
```

##### 2.1.3 启动后端服务
```bash
# 进入后端目录
cd backend

# 默认端口启动（8000）
uvicorn main:app --reload

# 指定端口启动
uvicorn main:app --reload --port 8001
```

#### 2.2 前端部署

##### 2.2.1 安装依赖
```bash
# 进入前端目录
cd frontend

# 安装前端依赖
npm install
```

##### 2.2.2 启动开发服务器
```bash
# 开发模式启动
npm run serve

# 生产环境构建
npm run build
```

## Docker 配置说明

### 1. 目录结构
```
vuln_manager/
├── docker-compose.yml    # Docker Compose 配置文件
├── backend/
│   ├── Dockerfile       # 后端 Dockerfile
│   └── ...
├── frontend/
│   ├── Dockerfile       # 前端 Dockerfile
│   └── ...
└── ...
```

### 2. 环境变量配置
```env
# 后端环境变量
BACKEND_PORT=8000
DATABASE_URL=sqlite:///./vuln.db

# 前端环境变量
VUE_APP_API_URL=http://localhost:8000
```

### 3. 数据持久化
- 数据库文件存储在 `./data` 目录
- 上传文件存储在 `./uploads` 目录

### 4. 网络配置
- 前端容器：8080端口
- 后端容器：8000端口
- 容器间通过内部网络通信

## 配置说明

### 后端配置

1. 数据库配置（backend/database.py）
```python
SQLALCHEMY_DATABASE_URL = "sqlite:///./vuln.db"
```

2. 端口配置（backend/main.py）
```python
# 默认端口为8000，可以通过启动命令修改
```

### 前端配置

1. API地址配置（frontend/src/views/VulnerabilityList.vue）
```javascript
// 修改API基础URL
const API_BASE_URL = "http://localhost:8000"
```

## 使用说明

### 1. 数据导入
- 点击"导入Excel"按钮
- 选择符合模板格式的Excel文件
- 系统会自动处理并导入数据

### 2. 数据筛选
- 支持多条件组合筛选
- 支持模糊搜索
- 支持精确匹配（如端口号）

### 3. 数据导出
- 点击"导出Excel"按钮
- 选择保存位置
- 导出当前筛选结果

### 4. 数据统计
- 漏洞等级分布
- 月度发现趋势
- 修复情况统计
- 状态分布

## 注意事项

### 数据安全
1. 定期备份数据库文件（vuln.db）
2. 生产环境建议使用更安全的数据库（如PostgreSQL）

### 性能优化
1. 大量数据导入时建议分批处理
2. 图表数据建议增加缓存机制
3. 生产环境部署时建议启用压缩

### 常见问题

1. 端口占用
```bash
# 检查端口占用
lsof -i :8000
# 修改端口
uvicorn main:app --reload --port 8001
```

2. 跨域问题
- 确保后端CORS配置正确
- 检查前端API地址配置

3. 数据导入失败
- 检查Excel文件格式是否符合模板要求
- 确保所有必填字段都已填写
- 检查日期格式是否正确

4. Docker相关问题
```bash
# 查看容器日志
docker-compose logs -f

# 重启服务
docker-compose restart

# 重建容器
docker-compose up -d --build

# 清理未使用的容器和镜像
docker system prune
```

## 维护建议

### 日常维护
1. 定期检查日志文件
2. 监控系统资源使用情况
3. 定期备份数据库

### 更新部署
1. 备份当前数据库
2. 更新代码
3. 执行数据库迁移（如果有）
4. 重启服务

## 故障排除

### 服务无法启动
1. 检查依赖是否安装完整
2. 检查端口是否被占用
3. 检查日志文件

### 数据异常
1. 检查数据库连接
2. 验证数据格式
3. 检查导入导出功能

### 性能问题
1. 检查数据库索引
2. 优化查询语句
3. 增加缓存机制

### Docker相关问题
1. 容器无法启动
   - 检查端口占用
   - 检查环境变量配置
   - 检查日志输出

2. 数据持久化问题
   - 检查数据卷挂载
   - 检查文件权限
   - 备份重要数据

3. 网络连接问题
   - 检查容器网络配置
   - 检查防火墙设置
   - 检查服务健康状态

## 更新日志

### v1.0.0
- 初始版本发布
- 基础功能实现
- 支持数据导入导出
- 支持数据统计和可视化

### v1.1.0
- 优化筛选功能
- 修复端口精确匹配问题
- 改进数据展示效果

### v1.2.0
- 添加Docker支持
- 优化部署流程
- 改进数据持久化

## 许可证

本项目采用 MIT 许可证，详情请查看 LICENSE 文件。 